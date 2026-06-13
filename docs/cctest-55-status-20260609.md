# CC Test 55 Status - 2026-06-09

## Scope

- Test environment only: FluxNode 8995 / New API channel 196 / test group `kiro-test`.
- Production Kiro RS ports 8992, 8993, and 8994 were not changed.
- Current test image: `fluxnode/kiro-rs:cc-test-adaptive-identity-8995-20260609`.

## External Result

Latest confirmed CC Test result:

- Result ID: `8353fe45-10d2-4c63-8ad2-204fbff6c7f9`
- Model: `claude-opus-4-8`
- Total score: 55%
- LLM fingerprint: pass
- Structure integrity: pass
- Behavior validation: 15 / 30
- Signature validation: fail
- Multimodal capability: pass

This commit archives the current 55% state before further CC Test signature and
behavior research.

## Implemented Compatibility Work

- Preserve real upstream `signature_delta` for Claude Code-shaped adaptive
  thinking requests.
- Keep adaptive thinking text hidden while still emitting a valid thinking block
  and upstream signature when present.
- Treat Claude Code as client context rather than model/provider/platform
  identity in identity probes.
- Preserve existing HVOY/API-CHECK-oriented compatibility work for model names,
  protocol shape, PDF text extraction, structured output, and SSE ordering.

## Verified Locally

- `cargo test anthropic::converter`
- `cargo test anthropic::handlers`
- `cargo test anthropic::stream`

## Remaining CC Test Issues

- CC Test still scores signature validation as failed.
- CC Test still gives behavior validation only 15 / 30.
- Next investigation direction: compare against real CC Max / Claude Max
  upstream channels and inspect their observable SSE signature and behavior
  shape under the same Claude Code-style request pattern.
