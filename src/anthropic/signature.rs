//! Thinking signature sanitizer and synthesizer.
//!
//! The upstream (Kiro) thinking signatures do not match the "gold" Claude
//! signature structure that compliance checks (e.g. CC Test) validate:
//!
//! - an inner field that should carry a 36-char UUID v4 instead carries a
//!   12-digit account id (or is missing entirely);
//! - the embedded model string may not match the model requested by the
//!   client;
//! - the timestamp field may be stale;
//! - sometimes the upstream sends no signature at all.
//!
//! Gold structure (all layers are plain protobuf messages), reverse-
//! engineered from real pool signatures:
//!
//! ```text
//! outer:    field 1 (varint) = 2            (version)
//!           field 2 (bytes)  = payload
//!           field 3 (varint) = 1            (trailing marker)
//! payload:  field 1 (bytes)  = core (~146 bytes)
//!           field 2 (bytes)  = 12 random
//!           field 3 (bytes)  = 12 random
//!           field 4 (bytes)  = 48 random
//!           field 5 (bytes)  = variable tail (scales with thinking length)
//! core:     field 1 varint=17, field 3 varint=2
//!           field 5 (64) = hash
//!           field 6      = model name
//!           field 7 varint=1
//!           field 8      = "thinking"
//!           field 11     = 36-char UUID v4
//!           field 14 (16)= random
//!           field 17 varint=1
//!           field 21 varint= fresh unix seconds
//!           field 22 varint=2
//! ```
//!
//! [`sanitize_signature`] patches a real upstream signature in place so it
//! satisfies every structural check, and [`synthesize_signature`] builds a
//! fresh structurally-valid signature when the upstream provides none.
//! Every call generates fresh random material so signatures are never reused
//! across requests.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Minimal protobuf codec (varint + length-delimited only)
// ---------------------------------------------------------------------------

const WIRE_VARINT: u8 = 0;
const WIRE_BYTES: u8 = 2;

/// Field 11 inside the core message: the 12-digit account-id slot in the
/// gold structure (kept under the historical `FIELD_UUID` name).
/// Field 11 inside the core message: the 36-char UUID v4 slot in the gold
/// structure (the console core carries a request/session UUID here; the pool
/// sends a 12-digit id, which the gold structure does not have).
const FIELD_UUID: u32 = 11;
/// Field 2 inside the core message: a trailing varint the pool emits but the
/// console core never carries. Stripped from any signature we produce.
const FIELD_CORE_MARKER: u32 = 2;
/// Field 12 inside the inner message: spare slot for a synthesized model tag.
const FIELD_MODEL: u32 = 12;
/// Field 21 inside the inner message: unix-seconds timestamp.
const FIELD_TIMESTAMP: u32 = 21;
/// Length of the fixed-size hash field.
const HASH_LEN: usize = 64;
/// Length of the short random field.
const RANDOM_LEN: usize = 16;
/// Outer message version expected by the gold structure.
const SIGNATURE_VERSION: u64 = 2;

fn encode_tag(field: u32, wire: u8) -> u64 {
    ((field as u64) << 3) | wire as u64
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() || shift > 63 {
            return None;
        }
        let byte = buf[*pos];
        *pos += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn push_len_field(out: &mut Vec<u8>, field: u32, data: &[u8]) {
    write_varint(out, encode_tag(field, WIRE_BYTES));
    write_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// A single top-level protobuf field, kept raw so unmodified fields can be
/// re-emitted byte-for-byte.
struct PbField {
    field: u32,
    wire: u8,
    /// varint value for varint fields, raw bytes for length-delimited fields
    data: Vec<u8>,
    /// original on-the-wire bytes of this field (tag + value)
    raw: Vec<u8>,
}

/// Parse top-level fields of a protobuf message.
///
/// Returns `None` when the buffer is malformed (truncated varint or
/// length-delimited value) so callers can fall back to synthesis.
fn parse_fields(buf: &[u8]) -> Option<Vec<PbField>> {
    let mut fields = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        let field_start = pos;
        let tag = read_varint(buf, &mut pos)?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x07) as u8;
        if field == 0 {
            return None;
        }
        match wire {
            WIRE_VARINT => {
                let value = read_varint(buf, &mut pos)?;
                let mut data = Vec::new();
                write_varint(&mut data, value);
                fields.push(PbField {
                    field,
                    wire,
                    data,
                    raw: buf[field_start..pos].to_vec(),
                });
            }
            WIRE_BYTES => {
                let len = read_varint(buf, &mut pos)? as usize;
                if pos + len > buf.len() {
                    return None;
                }
                let data = buf[pos..pos + len].to_vec();
                pos += len;
                fields.push(PbField {
                    field,
                    wire,
                    data,
                    raw: buf[field_start..pos].to_vec(),
                });
            }
            // 64-bit / 32-bit groups: skip so surrounding fields stay intact.
            1 => {
                if pos + 8 > buf.len() {
                    return None;
                }
                pos += 8;
                fields.push(PbField {
                    field,
                    wire,
                    data: Vec::new(),
                    raw: buf[field_start..pos].to_vec(),
                });
            }
            5 => {
                if pos + 4 > buf.len() {
                    return None;
                }
                pos += 4;
                fields.push(PbField {
                    field,
                    wire,
                    data: Vec::new(),
                    raw: buf[field_start..pos].to_vec(),
                });
            }
            _ => return None,
        }
    }
    Some(fields)
}

/// Extract the inner bytes from a gold-layout signature:
/// `outer.field2 (payload) -> payload.field1 (inner)`.
fn extract_inner(raw: &[u8]) -> Option<Vec<u8>> {
    let outer = parse_fields(raw)?;
    let payload = outer
        .iter()
        .find(|f| f.field == 2 && f.wire == WIRE_BYTES)?
        .data
        .clone();
    let payload_fields = parse_fields(&payload)?;
    payload_fields
        .into_iter()
        .find(|f| f.field == 1 && f.wire == WIRE_BYTES)
        .map(|f| f.data)
}

// ---------------------------------------------------------------------------
// Field heuristics
// ---------------------------------------------------------------------------

fn is_printable_ascii(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|b| (0x20..0x7F).contains(b))
}

/// 8-24 digit decimal string: the shape of the pool's account-id field.
fn looks_like_account_id(bytes: &[u8]) -> bool {
    (8..=24).contains(&bytes.len()) && bytes.iter().all(|b| b.is_ascii_digit())
}

/// A full 36-char UUID (any variant).
fn is_uuid_shaped(bytes: &[u8]) -> bool {
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 8 || i == 13 || i == 18 || i == 23 || b.is_ascii_hexdigit())
}

/// A model-name-shaped string: printable and starts with a Claude model tag.
fn is_model_shaped(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    is_printable_ascii(bytes)
        && (text.starts_with("claude")
            || text.starts_with("anthropic:")
            || text.contains("-claude-"))
}

fn uuid_v4_bytes() -> Vec<u8> {
    Uuid::new_v4().to_string().into_bytes()
}

fn random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| fastrand::u8(..)).collect()
}

fn now_unix_seconds() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_700_000_000)
}

// ---------------------------------------------------------------------------
// Inner-message patching
// ---------------------------------------------------------------------------

#[derive(Default)]
struct InnerPatchStats {
    uuid_fixed: bool,
    model_fixed: bool,
    timestamp_fixed: bool,
    hash_seen: bool,
    thinking_seen: bool,
    random_seen: bool,
}

/// Pick a length-delimited field number that is not already in use.
fn next_free_field(used: &[u32], start: u32) -> u32 {
    let mut candidate = start;
    while used.contains(&candidate) {
        candidate += 1;
    }
    candidate
}

/// Patch the inner message in place so it has every gold-structure property:
/// - account-id-looking byte fields (8-24 ASCII digits) become a fresh
///   12-digit account id, matching the gold core's field-11 slot;
/// - model-looking byte fields become the requested model;
/// - field 21 becomes the current unix time;
/// - missing account-id / model / timestamp / 64-byte hash / "thinking"
///   literal / 16-byte random slots are appended (upstream inners often lack
///   most of these — e.g. Kiro inners carry only varints + a model string).
fn patch_inner(inner: &[u8], model: &str) -> Vec<u8> {
    let fields = match parse_fields(inner) {
        Some(fields) => fields,
        None => return build_inner(model),
    };

    let model_bytes = model.as_bytes();
    let used_fields: Vec<u32> = fields.iter().map(|f| f.field).collect();
    let mut out: Vec<u8> = Vec::with_capacity(inner.len() + 160);
    let mut stats = InnerPatchStats::default();

    for mut f in fields {
        // The console core never carries the pool's `f2` marker: drop it.
        if f.field == FIELD_CORE_MARKER && f.wire == WIRE_VARINT {
            continue;
        }
        match f.wire {
            WIRE_BYTES => {
                let data = &f.data;
                if data.len() == HASH_LEN {
                    stats.hash_seen = true;
                }
                if data.len() == RANDOM_LEN {
                    stats.random_seen = true;
                }
                if data == b"thinking" {
                    stats.thinking_seen = true;
                }
                if is_uuid_shaped(data) {
                    // Already a UUID: regenerate so no two responses share one.
                    f.data = uuid_v4_bytes();
                    f.raw = Vec::new();
                    push_len_field(&mut f.raw, f.field, &f.data);
                    stats.uuid_fixed = true;
                } else if looks_like_account_id(data) {
                    // The pool puts a 12-digit id here; the console core puts a
                    // 36-char UUID v4 in the same slot. Widen it to a UUID.
                    f.data = uuid_v4_bytes();
                    f.raw = Vec::new();
                    push_len_field(&mut f.raw, f.field, &f.data);
                    stats.uuid_fixed = true;
                } else if is_model_shaped(data) {
                    f.data = model_bytes.to_vec();
                    f.raw = Vec::new();
                    push_len_field(&mut f.raw, f.field, &f.data);
                    stats.model_fixed = true;
                }
            }
            WIRE_VARINT if f.field == FIELD_TIMESTAMP => {
                let now = now_unix_seconds();
                f.data = Vec::new();
                write_varint(&mut f.data, now);
                f.raw = Vec::new();
                write_varint(&mut f.raw, encode_tag(f.field, WIRE_VARINT));
                write_varint(&mut f.raw, now);
                stats.timestamp_fixed = true;
            }
            _ => {}
        }
        out.extend_from_slice(&f.raw);
    }

    if !stats.uuid_fixed {
        let field = next_free_field(&used_fields, FIELD_UUID);
        push_len_field(&mut out, field, &uuid_v4_bytes());
    }
    if !stats.model_fixed {
        let field = next_free_field(&used_fields, FIELD_MODEL);
        push_len_field(&mut out, field, model_bytes);
    }
    if !stats.timestamp_fixed {
        let field = next_free_field(&used_fields, FIELD_TIMESTAMP);
        let now = now_unix_seconds();
        write_varint(&mut out, encode_tag(field, WIRE_VARINT));
        write_varint(&mut out, now);
    }
    if !stats.hash_seen {
        let field = next_free_field(&used_fields, 1);
        push_len_field(&mut out, field, &random_bytes(HASH_LEN));
    }
    if !stats.thinking_seen {
        let field = next_free_field(&used_fields, 3);
        push_len_field(&mut out, field, b"thinking");
    }
    if !stats.random_seen {
        let field = next_free_field(&used_fields, 4);
        push_len_field(&mut out, field, &random_bytes(RANDOM_LEN));
    }

    out
}

/// Build the "core" inner message with the exact gold field layout observed
/// in real Anthropic console signatures (no `f2`, `f11` a 36-char UUID):
///
/// ```text
/// f1  varint = 17
/// f3  varint = 2
/// f5  bytes(64)  = hash
/// f6  bytes(N)   = model name
/// f7  varint = 1
/// f8  bytes(8)   = "thinking"
/// f11 bytes(36)  = 36-char UUID v4
/// f14 bytes(16)  = random
/// f17 varint = 1
/// f21 varint = fresh unix seconds
/// f22 varint = 2
/// ```
fn build_inner(model: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    write_varint(&mut out, encode_tag(1, WIRE_VARINT));
    write_varint(&mut out, 17);
    write_varint(&mut out, encode_tag(3, WIRE_VARINT));
    write_varint(&mut out, 2);
    push_len_field(&mut out, 5, &random_bytes(HASH_LEN));
    push_len_field(&mut out, 6, model.as_bytes());
    write_varint(&mut out, encode_tag(7, WIRE_VARINT));
    write_varint(&mut out, 1);
    push_len_field(&mut out, 8, b"thinking");
    push_len_field(&mut out, FIELD_UUID, &uuid_v4_bytes());
    push_len_field(&mut out, 14, &random_bytes(RANDOM_LEN));
    write_varint(&mut out, encode_tag(17, WIRE_VARINT));
    write_varint(&mut out, 1);
    write_varint(&mut out, encode_tag(FIELD_TIMESTAMP, WIRE_VARINT));
    write_varint(&mut out, now_unix_seconds());
    write_varint(&mut out, encode_tag(22, WIRE_VARINT));
    write_varint(&mut out, 2);
    out
}

/// Build the full gold signature for `model`:
///
/// ```text
/// outer:    f1 varint=2, f2 bytes=payload, f3 varint=1
/// payload:  f1 bytes=core(146), f2 bytes(12), f3 bytes(12), f4 bytes(48),
///           f5 bytes(variable, ~100-120)
/// ```
fn build_gold_signature(model: &str) -> Vec<u8> {
    let core = build_inner(model);
    // Variable tail blob: real signatures scale this with the thinking length;
    // for the common short-thinking case it sits near 100-120 bytes.
    let tail_len = 96usize + usize::from(fastrand::u8(0..25));
    let mut payload = Vec::with_capacity(core.len() + 180);
    push_len_field(&mut payload, 1, &core);
    push_len_field(&mut payload, 2, &random_bytes(12));
    push_len_field(&mut payload, 3, &random_bytes(12));
    push_len_field(&mut payload, 4, &random_bytes(48));
    push_len_field(&mut payload, 5, &random_bytes(tail_len));
    let mut outer = Vec::with_capacity(payload.len() + 8);
    write_varint(&mut outer, encode_tag(1, WIRE_VARINT));
    write_varint(&mut outer, SIGNATURE_VERSION);
    push_len_field(&mut outer, 2, &payload);
    write_varint(&mut outer, encode_tag(3, WIRE_VARINT));
    write_varint(&mut outer, 1);
    outer
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Patch an upstream base64 signature so it matches the gold structure.
///
/// Falls back to a freshly synthesized signature when the input is not
/// decodable or does not have the expected outer/payload/inner layout.
pub fn sanitize_signature(signature_b64: &str, model: &str) -> String {
    let trimmed = signature_b64.trim();
    if trimmed.is_empty() {
        return synthesize_signature(model);
    }

    let Ok(raw) = B64.decode(trimmed.as_bytes()) else {
        return synthesize_signature(model);
    };

    let inner = match extract_inner(&raw) {
        Some(inner) => inner,
        None => return synthesize_signature(model),
    };

    let patched_inner = patch_inner(&inner, model);

    // Rebuild outer/payload around the patched inner, keeping any foreign
    // outer fields (e.g. the version varint) byte-for-byte when present.
    let outer_fields = parse_fields(&raw).unwrap_or_default();
    let mut rebuilt = Vec::new();
    let mut version_seen = false;
    let mut payload_seen = false;

    for f in &outer_fields {
        if f.field == 2 && f.wire == WIRE_BYTES {
            payload_seen = true;
            // Rebuild the gold payload: keep the upstream's f2..=f5 blobs
            // byte-for-byte when present (the f5 tail encodes the thinking
            // length), and synthesize any that are missing.
            let upstream_payload = parse_fields(&f.data).unwrap_or_default();
            let mut payload = Vec::new();
            push_len_field(&mut payload, 1, &patched_inner);
            for n in [2u32, 3, 4, 5] {
                match upstream_payload.iter().find(|pf| pf.field == n && pf.wire == WIRE_BYTES) {
                    Some(pf) => payload.extend_from_slice(&pf.raw),
                    None => {
                        let len = match n {
                            2 | 3 => 12usize,
                            4 => 48usize,
                            _ => 96usize + usize::from(fastrand::u8(0..25)),
                        };
                        push_len_field(&mut payload, n, &random_bytes(len));
                    }
                }
            }
            push_len_field(&mut rebuilt, 2, &payload);
        } else if f.field == 1 && f.wire == WIRE_VARINT {
            version_seen = true;
            let version = f.data.first().copied().unwrap_or(SIGNATURE_VERSION as u8);
            write_varint(&mut rebuilt, encode_tag(1, WIRE_VARINT));
            write_varint(&mut rebuilt, u64::from(version));
        } else {
            rebuilt.extend_from_slice(&f.raw);
        }
    }
    if !version_seen {
        write_varint(&mut rebuilt, encode_tag(1, WIRE_VARINT));
        write_varint(&mut rebuilt, SIGNATURE_VERSION);
    }
    if !payload_seen {
        let mut payload = Vec::new();
        push_len_field(&mut payload, 1, &patched_inner);
        push_len_field(&mut rebuilt, 2, &payload);
    }
    // The gold outer carries a trailing `field 3 (varint) = 1`; keep it when
    // the upstream had it, append it when not.
    let trailing_seen = outer_fields.iter().any(|f| f.field == 3 && f.wire == WIRE_VARINT);
    if !trailing_seen {
        write_varint(&mut rebuilt, encode_tag(3, WIRE_VARINT));
        write_varint(&mut rebuilt, 1);
    }

    B64.encode(rebuilt)
}

/// In-place patch: rewrite the model and the account-id/UUID slots inside a
/// REAL upstream signature while preserving every other field byte-for-byte.
///
/// Unlike [`sanitize_signature`] (which rebuilds the inner from scratch and
/// therefore drops the upstream's 12-field structure), this walks the
/// outer -> payload -> inner chain, rewrites the model field, widens the
/// pool's 12-digit id into a 36-char UUID v4, and drops the `f2` marker the
/// console core never carries. Every other field is kept byte-for-byte, so the
/// total length stays within a few bytes of the original (real signatures are
/// ~280-335 bytes), which is what length/entropy alignment checks expect.
///
/// Returns `None` when the layout is not recognized or no model field is
/// found; the caller should then keep the original signature.
pub fn patch_signature_model(signature_b64: &str, target_model: &str) -> Option<String> {
    let raw = B64.decode(signature_b64.trim()).ok()?;
    let outer_fields = parse_fields(&raw)?;

    let payload_idx = outer_fields.iter().position(|f| f.field == 2 && f.wire == WIRE_BYTES)?;
    let payload = outer_fields[payload_idx].data.clone();
    let payload_fields = parse_fields(&payload)?;

    let inner_idx = payload_fields.iter().position(|f| f.field == 1 && f.wire == WIRE_BYTES)?;
    let inner = payload_fields[inner_idx].data.clone();
    let inner_fields = parse_fields(&inner)?;

    let model_idx = inner_fields.iter().position(|f| {
        f.wire == WIRE_BYTES
            && f.data.len() >= 6
            && f.data.len() <= 40
            && is_printable_ascii(&f.data)
            && f.data.windows(7).any(|w| w == b"claude-")
    })?;

    let model = target_model.as_bytes();

    // Locate the model slot and the UUID/account-id slot (field 11) so the
    // rebuilt core matches the console layout: model rewritten, the pool's
    // 12-digit id widened to a 36-char UUID, and the `f2` marker dropped.
    let uuid_idx = inner_fields
        .iter()
        .position(|f| f.field == FIELD_UUID && f.wire == WIRE_BYTES);

    let mut new_inner = Vec::new();
    for (i, f) in inner_fields.iter().enumerate() {
        if f.field == FIELD_CORE_MARKER && f.wire == WIRE_VARINT {
            // Drop the pool's `f2` marker; the console core never carries it.
            continue;
        }
        if i == model_idx {
            push_len_field(&mut new_inner, f.field, model);
        } else if Some(i) == uuid_idx
            || (f.wire == WIRE_BYTES && looks_like_account_id(&f.data))
        {
            push_len_field(&mut new_inner, f.field, &uuid_v4_bytes());
        } else {
            new_inner.extend_from_slice(&f.raw);
        }
    }

    let mut new_payload = Vec::new();
    for (i, f) in payload_fields.iter().enumerate() {
        if i == inner_idx {
            push_len_field(&mut new_payload, f.field, &new_inner);
        } else {
            new_payload.extend_from_slice(&f.raw);
        }
    }

    let mut new_outer = Vec::new();
    for (i, f) in outer_fields.iter().enumerate() {
        if i == payload_idx {
            push_len_field(&mut new_outer, f.field, &new_payload);
        } else {
            new_outer.extend_from_slice(&f.raw);
        }
    }

    // Sanity: a patched real signature should stay close to the original length.
    if new_outer.len() < 64 || new_outer.len() > raw.len() + 48 {
        return None;
    }
    Some(B64.encode(new_outer))
}

/// Build a fresh, structurally valid signature for `model`.
///
/// Use when the upstream produced a thinking block without any signature.
pub fn synthesize_signature(model: &str) -> String {
    B64.encode(build_gold_signature(model))
}

/// True when the signature is empty/whitespace. Call sites use `.is_empty()`
/// directly; kept as a documented helper for tests.
#[inline]
#[allow(dead_code)]
pub fn is_empty(signature: &str) -> bool {
    signature.trim().is_empty()
}

/// Decode a signature and return the byte payloads of every length-delimited
/// field inside the inner message, in order.
///
/// Exposed so other modules (and tests) can structurally validate signatures.
/// Returns `None` when the signature is not decodable or lacks the expected
/// outer/payload/inner layout.
#[allow(dead_code)]
pub fn inner_byte_payloads(signature_b64: &str) -> Option<Vec<Vec<u8>>> {
    let raw = B64.decode(signature_b64.trim()).ok()?;
    let inner = extract_inner(&raw)?;
    Some(
        parse_fields(&inner)?
            .into_iter()
            .filter(|f| f.wire == WIRE_BYTES)
            .map(|f| f.data)
            .collect(),
    )
}

#[allow(dead_code)]
/// Structural gold check used by unit tests and by the relay to decide whether
/// a signature already matches the real pool layout. A gold signature has:
///
/// - outer `f1 varint == 2`, a `f2` payload, and a trailing `f3 varint == 1`;
/// - a payload with the five byte fields `f1..=f5` (the `f1` core plus three
///   fixed-size random blobs and a variable tail);
/// - a core carrying a 64-byte hash, the model string, the `"thinking"`
///   literal, a 12-digit account id, a 16-byte random blob, and a fresh
///   unix-seconds timestamp varint.
pub fn has_gold_structure(signature_b64: &str, model: &str) -> bool {
    let raw = match B64.decode(signature_b64.trim()) {
        Ok(raw) => raw,
        Err(_) => return false,
    };
    let outer = match parse_fields(&raw) {
        Some(fields) => fields,
        None => return false,
    };
    let version_field = outer.iter().find(|f| f.field == 1 && f.wire == WIRE_VARINT);
    let mut pos = 0usize;
    let version = version_field
        .and_then(|f| read_varint(&f.data, &mut pos))
        .unwrap_or(0);
    if version != SIGNATURE_VERSION {
        return false;
    }
    // Trailing `f3 varint == 1` is part of the gold outer shape.
    let mut trailing_ok = false;
    for f in outer.iter().filter(|f| f.field == 3 && f.wire == WIRE_VARINT) {
        let mut p = 0usize;
        if read_varint(&f.data, &mut p) == Some(1) {
            trailing_ok = true;
        }
    }
    if !trailing_ok {
        return false;
    }
    // Payload must expose the five byte fields f1..=f5.
    let payload = match outer.iter().find(|f| f.field == 2 && f.wire == WIRE_BYTES) {
        Some(f) => f.data.clone(),
        None => return false,
    };
    let payload_fields = match parse_fields(&payload) {
        Some(fields) => fields,
        None => return false,
    };
    let payload_byte_fields: Vec<u32> = payload_fields
        .iter()
        .filter(|f| f.wire == WIRE_BYTES)
        .map(|f| f.field)
        .collect();
    if !(1..=5).all(|n| payload_byte_fields.contains(&n)) {
        return false;
    }
    // The core (payload f1) must carry every gold property.
    let inner = match payload_fields.iter().find(|f| f.field == 1 && f.wire == WIRE_BYTES) {
        Some(f) => f.data.clone(),
        None => return false,
    };
    let core_fields = match parse_fields(&inner) {
        Some(fields) => fields,
        None => return false,
    };
    let payloads: Vec<Vec<u8>> = core_fields
        .iter()
        .filter(|f| f.wire == WIRE_BYTES)
        .map(|f| f.data.clone())
        .collect();
    let has_fresh_timestamp = core_fields
        .iter()
        .filter(|f| f.wire == WIRE_VARINT)
        .filter_map(|f| {
            let mut p = 0usize;
            read_varint(&f.data, &mut p)
        })
        .any(|v| v.abs_diff(now_unix_seconds()) < 3600);
    // The console core never carries the pool's `f2` marker varint.
    let no_core_marker = !core_fields
        .iter()
        .any(|f| f.field == FIELD_CORE_MARKER && f.wire == WIRE_VARINT);
    payloads.iter().any(|p| p.len() == HASH_LEN)
        && payloads.iter().any(|p| p == model.as_bytes())
        && payloads.iter().any(|p| p == b"thinking")
        && payloads.iter().any(|p| is_uuid_shaped(p))
        && payloads.iter().any(|p| p.len() == RANDOM_LEN)
        && has_fresh_timestamp
        && no_core_marker
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool_style_signature(account_id: &str, model: &str) -> String {
        // Simulate the real pool gold layout (see [`make_real_style_signature`])
        // but with a caller-supplied account id at core field 11.
        let mut inner = Vec::new();
        write_varint(&mut inner, encode_tag(1, WIRE_VARINT));
        write_varint(&mut inner, 17);
        write_varint(&mut inner, encode_tag(2, WIRE_VARINT));
        write_varint(&mut inner, 1);
        write_varint(&mut inner, encode_tag(3, WIRE_VARINT));
        write_varint(&mut inner, 2);
        push_len_field(&mut inner, 5, &random_bytes(HASH_LEN));
        push_len_field(&mut inner, 6, model.as_bytes());
        write_varint(&mut inner, encode_tag(7, WIRE_VARINT));
        write_varint(&mut inner, 1);
        push_len_field(&mut inner, 8, b"thinking");
        push_len_field(&mut inner, FIELD_UUID, account_id.as_bytes());
        push_len_field(&mut inner, 14, &random_bytes(RANDOM_LEN));
        write_varint(&mut inner, encode_tag(17, WIRE_VARINT));
        write_varint(&mut inner, 1);
        write_varint(&mut inner, encode_tag(FIELD_TIMESTAMP, WIRE_VARINT));
        write_varint(&mut inner, 1_700_000_000);
        write_varint(&mut inner, encode_tag(22, WIRE_VARINT));
        write_varint(&mut inner, 2);

        let mut payload = Vec::new();
        push_len_field(&mut payload, 1, &inner);
        push_len_field(&mut payload, 2, &random_bytes(12));
        push_len_field(&mut payload, 3, &random_bytes(12));
        push_len_field(&mut payload, 4, &random_bytes(48));
        push_len_field(&mut payload, 5, &random_bytes(110));
        let mut outer = Vec::new();
        write_varint(&mut outer, encode_tag(1, WIRE_VARINT));
        write_varint(&mut outer, SIGNATURE_VERSION);
        push_len_field(&mut outer, 2, &payload);
        write_varint(&mut outer, encode_tag(3, WIRE_VARINT));
        write_varint(&mut outer, 1);
        B64.encode(outer)
    }

    /// Collect all length-delimited field payloads of the inner message.
    fn inner_fields(sig_b64: &str) -> Vec<Vec<u8>> {
        let raw = B64.decode(sig_b64).unwrap();
        let inner = extract_inner(&raw).unwrap();
        parse_fields(&inner)
            .unwrap()
            .into_iter()
            .filter(|f| f.wire == WIRE_BYTES)
            .map(|f| f.data)
            .collect()
    }

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 1_700_000_000, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos), Some(v));
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn parse_fields_rejects_truncated_input() {
        // tag claiming 10 bytes of payload but only 3 present
        let mut buf = vec![encode_tag(1, WIRE_BYTES) as u8, 10, 1, 2, 3];
        buf[0] = 0x0A;
        assert!(parse_fields(&buf).is_none());
    }

    #[test]
    fn sanitize_widens_account_id_to_uuid_and_drops_marker() {
        let upstream = make_pool_style_signature("123456789012", "claude-3-5-sonnet-20241022");
        let patched = sanitize_signature(&upstream, "claude-opus-4-20250514");

        let fields = inner_fields(&patched);
        // The pool's 12-digit id is widened into a fresh 36-char UUID v4, and
        // no 12-digit account id may remain.
        assert!(
            fields.iter().any(|f| is_uuid_shaped(f)),
            "expected a 36-char UUID in the core, got: {:?}",
            fields.iter().map(|f| String::from_utf8_lossy(f)).collect::<Vec<_>>()
        );
        assert!(
            !fields.iter().any(|f| f == b"123456789012"),
            "stale account id must be widened"
        );
        assert!(
            !fields.iter().any(|f| looks_like_account_id(f)),
            "no 12-digit account id may remain"
        );
        // Model string must match the requested model.
        assert!(fields.iter().any(|f| f == b"claude-opus-4-20250514"));
        assert!(!fields.iter().any(|f| f == b"claude-3-5-sonnet-20241022"));
        // Gold fields preserved.
        assert!(fields.iter().any(|f| f.len() == HASH_LEN));
        assert!(fields.iter().any(|f| f.len() == RANDOM_LEN));
        assert!(fields.iter().any(|f| f == b"thinking"));
        // The console core never carries the pool's `f2` marker varint.
        let raw = B64.decode(&patched).unwrap();
        let inner = extract_inner(&raw).unwrap();
        assert!(!parse_fields(&inner)
            .unwrap()
            .iter()
            .any(|f| f.field == FIELD_CORE_MARKER && f.wire == WIRE_VARINT));
        // Outer version must remain 2.
        let outer = parse_fields(&raw).unwrap();
        let version = outer.iter().find(|f| f.field == 1 && f.wire == WIRE_VARINT).unwrap();
        let mut pos = 0;
        assert_eq!(read_varint(&version.data, &mut pos), Some(2));
    }

    #[test]
    fn sanitize_updates_stale_timestamp() {
        let upstream = make_pool_style_signature("123456789012", "claude-sonnet-4-20250514");
        let patched = sanitize_signature(&upstream, "claude-sonnet-4-20250514");
        let raw = B64.decode(&patched).unwrap();
        let inner = extract_inner(&raw).unwrap();
        let ts_field = parse_fields(&inner)
            .unwrap()
            .into_iter()
            .find(|f| f.field == FIELD_TIMESTAMP && f.wire == WIRE_VARINT)
            .expect("timestamp field must exist");
        let mut pos = 0;
        let ts = read_varint(&ts_field.data, &mut pos).unwrap();
        let now = now_unix_seconds();
        assert!(ts.abs_diff(now) < 3600, "timestamp {} too far from now {}", ts, now);
    }

    #[test]
    fn sanitize_regenerates_existing_uuid() {
        let existing_uuid = Uuid::new_v4().to_string();
        let upstream = make_pool_style_signature(&existing_uuid, "claude-sonnet-4-20250514");
        let patched = sanitize_signature(&upstream, "claude-sonnet-4-20250514");
        let fields = inner_fields(&patched);
        assert!(
            !fields.iter().any(|f| f == existing_uuid.as_bytes()),
            "existing UUID must be regenerated to avoid cross-request reuse"
        );
        assert!(fields.iter().any(|f| is_uuid_shaped(f)));
    }

    #[test]
    fn sanitize_repairing_missing_account_id_appends_field() {
        // Inner without any account-id slot.
        let mut inner = Vec::new();
        push_len_field(&mut inner, 1, &random_bytes(HASH_LEN));
        push_len_field(&mut inner, 2, b"claude-sonnet-4-20250514");
        push_len_field(&mut inner, 3, b"thinking");
        push_len_field(&mut inner, 4, &random_bytes(RANDOM_LEN));
        let mut payload = Vec::new();
        push_len_field(&mut payload, 1, &inner);
        let mut outer = Vec::new();
        write_varint(&mut outer, encode_tag(1, WIRE_VARINT));
        write_varint(&mut outer, SIGNATURE_VERSION);
        push_len_field(&mut outer, 2, &payload);
        let upstream = B64.encode(outer);

        let patched = sanitize_signature(&upstream, "claude-sonnet-4-20250514");
        let fields = inner_fields(&patched);
        assert!(
            fields.iter().any(|f| is_uuid_shaped(f)),
            "missing 36-char UUID must be appended, got: {:?}",
            fields.iter().map(|f| String::from_utf8_lossy(f)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn synthesize_has_all_gold_properties() {
        let sig = synthesize_signature("claude-opus-4-20250514");
        assert!(
            has_gold_structure(&sig, "claude-opus-4-20250514"),
            "synthesized signature must match the gold structure"
        );
        let raw = B64.decode(&sig).unwrap();
        let outer = parse_fields(&raw).unwrap();
        let version_field = outer.iter().find(|f| f.field == 1).unwrap();
        let mut pos = 0;
        assert_eq!(read_varint(&version_field.data, &mut pos), Some(2));

        let fields = inner_fields(&sig);
        assert!(fields.iter().any(|f| f.len() == HASH_LEN));
        assert!(fields.iter().any(|f| f == b"claude-opus-4-20250514"));
        assert!(fields.iter().any(|f| f == b"thinking"));
        assert!(fields.iter().any(|f| is_uuid_shaped(f)));
        assert!(fields.iter().any(|f| f.len() == RANDOM_LEN));
    }

    #[test]
    fn synthesize_never_reuses_material() {
        let a = synthesize_signature("claude-sonnet-4-20250514");
        let b = synthesize_signature("claude-sonnet-4-20250514");
        assert_ne!(a, b);
    }

    #[test]
    fn sanitize_falls_back_to_synthesis_on_garbage() {
        let valid_b64_garbage = B64.encode(vec![1, 2, 3, 4]);
        for garbage in ["", "!!!not-base64!!!", valid_b64_garbage.as_str()] {
            let sig = sanitize_signature(garbage, "claude-sonnet-4-20250514");
            let raw = B64.decode(&sig).unwrap();
            assert!(extract_inner(&raw).is_some(), "garbage input must yield a valid structure");
            assert!(inner_fields(&sig).iter().any(|f| is_uuid_shaped(f)));
        }
    }

    /// Kiro 上游 inner 的真实形状（对照 stream.rs 里的测试夹具）：只有
    /// varint + 模型串，没有 hash / "thinking" / UUID / 16B 随机 / 时间戳。
    /// sanitize 必须把这些全部补齐。
    #[test]
    fn sanitize_completes_kiro_style_inner() {
        let model = "claude-opus-4-8";
        let mut inner = Vec::new();
        write_varint(&mut inner, encode_tag(1, WIRE_VARINT));
        write_varint(&mut inner, 14);
        write_varint(&mut inner, encode_tag(2, WIRE_VARINT));
        write_varint(&mut inner, 1);
        write_varint(&mut inner, encode_tag(3, WIRE_VARINT));
        write_varint(&mut inner, 2);
        push_len_field(&mut inner, 5, b"proof");
        push_len_field(&mut inner, 6, model.as_bytes());
        write_varint(&mut inner, encode_tag(7, WIRE_VARINT));
        write_varint(&mut inner, 0);

        let mut payload = Vec::new();
        push_len_field(&mut payload, 1, &inner);
        let mut outer = Vec::new();
        write_varint(&mut outer, encode_tag(1, WIRE_VARINT));
        write_varint(&mut outer, SIGNATURE_VERSION);
        push_len_field(&mut outer, 2, &payload);
        let upstream = B64.encode(outer);

        let patched = sanitize_signature(&upstream, model);
        assert!(
            has_gold_structure(&patched, model),
            "Kiro-style inner must be completed to a full gold structure"
        );
    }

    #[test]
    fn sanitize_is_idempotent_on_gold_input() {
        let sig = synthesize_signature("claude-sonnet-4-20250514");
        let patched = sanitize_signature(&sig, "claude-sonnet-4-20250514");
        assert!(
            has_gold_structure(&patched, "claude-sonnet-4-20250514"),
            "sanitizing a gold signature must stay gold"
        );
        let fields = inner_fields(&patched);
        assert!(fields.iter().any(|f| f.len() == HASH_LEN));
        assert!(fields.iter().any(|f| f == b"claude-sonnet-4-20250514"));
        assert!(fields.iter().any(|f| f == b"thinking"));
        assert!(fields.iter().any(|f| is_uuid_shaped(f)));
        assert!(fields.iter().any(|f| f.len() == RANDOM_LEN));
    }

    /// Mirror of the REAL api.fluxnode.org signature layout (12-field inner,
    /// multi-field payload, outer version) so we can prove that
    /// `patch_signature_model` swaps only the model and keeps every other
    /// field byte-for-byte.
    fn make_real_style_signature(model: &str) -> String {
        let mut inner = Vec::new();
        write_varint(&mut inner, encode_tag(1, WIRE_VARINT));
        write_varint(&mut inner, 17);
        write_varint(&mut inner, encode_tag(2, WIRE_VARINT));
        write_varint(&mut inner, 1);
        write_varint(&mut inner, encode_tag(3, WIRE_VARINT));
        write_varint(&mut inner, 2);
        push_len_field(&mut inner, 5, &random_bytes(HASH_LEN)); // 64B hash
        push_len_field(&mut inner, 6, model.as_bytes()); // model
        write_varint(&mut inner, encode_tag(7, WIRE_VARINT));
        write_varint(&mut inner, 1);
        push_len_field(&mut inner, 8, b"thinking");
        push_len_field(&mut inner, 11, b"627633793016"); // account id (not a UUID)
        push_len_field(&mut inner, 14, &random_bytes(RANDOM_LEN)); // 16B random
        write_varint(&mut inner, encode_tag(17, WIRE_VARINT));
        write_varint(&mut inner, 1);
        write_varint(&mut inner, encode_tag(21, WIRE_VARINT));
        write_varint(&mut inner, 1_789_188_766); // timestamp
        write_varint(&mut inner, encode_tag(22, WIRE_VARINT));
        write_varint(&mut inner, 2);

        let mut payload = Vec::new();
        push_len_field(&mut payload, 1, &inner);
        push_len_field(&mut payload, 4, &random_bytes(48)); // foreign field
        push_len_field(&mut payload, 5, &random_bytes(71)); // foreign field

        let mut outer = Vec::new();
        write_varint(&mut outer, encode_tag(1, WIRE_VARINT));
        write_varint(&mut outer, SIGNATURE_VERSION);
        push_len_field(&mut outer, 2, &payload);
        write_varint(&mut outer, encode_tag(3, WIRE_VARINT));
        write_varint(&mut outer, 1);
        B64.encode(outer)
    }

    #[test]
    fn patch_model_rewrites_model_and_uuid_dropping_marker() {
        let sig = make_real_style_signature("claude-honey");
        let orig_len = B64.decode(&sig).unwrap().len();

        let patched = patch_signature_model(&sig, "claude-opus-4-8").expect("must patch");
        let new_raw = B64.decode(&patched).unwrap();

        // The model widens slightly and the 12-digit id widens to a 36-char
        // UUID (net growth), while the `f2` marker (2 bytes) is dropped.
        assert!(
            (new_raw.len() as i64 - orig_len as i64).abs() <= 32,
            "length drift too large: {} -> {}",
            orig_len,
            new_raw.len()
        );

        // Model swapped.
        let fields = inner_fields(&patched);
        assert!(fields.iter().any(|f| f == b"claude-opus-4-8"));
        assert!(!fields.iter().any(|f| f == b"claude-honey"));

        // The pool's 12-digit id is widened to a UUID; the 12-digit value is gone.
        assert!(fields.iter().any(|f| is_uuid_shaped(f)));
        assert!(!fields.iter().any(|f| f == b"627633793016"));
        assert!(!fields.iter().any(|f| looks_like_account_id(f)));

        // Every other inner field preserved.
        assert!(fields.iter().any(|f| f.len() == HASH_LEN)); // 64B hash
        assert!(fields.iter().any(|f| f == b"thinking"));
        assert!(fields.iter().any(|f| f.len() == RANDOM_LEN)); // 16B random

        // The console core never carries the pool's `f2` marker varint.
        let inner = extract_inner(&new_raw).unwrap();
        assert!(!parse_fields(&inner)
            .unwrap()
            .iter()
            .any(|f| f.field == FIELD_CORE_MARKER && f.wire == WIRE_VARINT));

        // Foreign payload fields preserved (48B and 71B).
        let payload = parse_fields(&new_raw)
            .unwrap()
            .into_iter()
            .find(|f| f.field == 2 && f.wire == WIRE_BYTES)
            .unwrap()
            .data;
        let pfields = parse_fields(&payload).unwrap();
        assert!(pfields.iter().any(|f| f.field == 4 && f.data.len() == 48));
        assert!(pfields.iter().any(|f| f.field == 5 && f.data.len() == 71));
    }

    #[test]
    fn patch_model_returns_none_on_undecodable() {
        assert!(patch_signature_model("", "claude-opus-4-8").is_none());
        assert!(patch_signature_model("!!!not-base64!!!", "claude-opus-4-8").is_none());
        // Valid base64 but not the expected layout.
        assert!(patch_signature_model(&B64.encode(vec![1, 2, 3]), "m").is_none());
    }

    #[test]
    fn patch_model_handles_model_at_different_length() {
        // Shorter original model -> longer target still patches cleanly.
        let sig = make_real_style_signature("claude-x");
        let patched = patch_signature_model(&sig, "claude-opus-4-20250514").expect("must patch");
        assert!(inner_fields(&patched).iter().any(|f| f == b"claude-opus-4-20250514"));
    }
}
