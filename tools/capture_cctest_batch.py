#!/usr/bin/env python3
"""
Summarize the latest CC Test batch for the 8995 test channel.

Run this on fluxnode-target. It is read-only: it queries New API logs and scans
TAP records, then correlates them by time, model, prompt token count, and the
metadata session_id used by cctest.ai.
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Any


DEFAULT_TAP_ROOT = "/data/tap/side-tee-live"

MARKERS = [
    ("<32f41bf6a6390b1c>", "tag"),
    ("identity_platform", "identity_json"),
    ("1+1", "math"),
    ("谁养鱼", "web_or_logic"),
    ("养鱼", "identity_or_web"),
    ("2EGYFF", "image"),
    ("WTMUH7KQ", "pdf"),
]


@dataclass(frozen=True)
class LogRow:
    id: int
    created_epoch: int
    created_at: str
    token_id: int
    channel_id: int
    prompt_tokens: int
    completion_tokens: int
    request_id: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="claude-opus-4-8")
    parser.add_argument("--token-id", type=int, default=795)
    parser.add_argument("--channel-id", type=int, default=196)
    parser.add_argument("--minutes", type=int, default=90)
    parser.add_argument("--after-epoch", type=int, help="Only include New API logs after this epoch second")
    parser.add_argument("--date", help="TAP date folder, for example 20260609")
    parser.add_argument("--session-id", help="Force a TAP metadata session_id")
    parser.add_argument("--tap-root", default=DEFAULT_TAP_ROOT)
    parser.add_argument("--out", help="Optional JSON output file")
    return parser.parse_args()


def run_psql_logs(args: argparse.Namespace) -> list[LogRow]:
    after_clause = ""
    if args.after_epoch:
        after_clause = f"  AND created_at > {args.after_epoch}\n"

    query = f"""
SET statement_timeout='20s';
SELECT id,
       created_at,
       to_char(to_timestamp(created_at),'YYYY-MM-DD HH24:MI:SS'),
       token_id,
       channel_id,
       prompt_tokens,
       completion_tokens,
       request_id
FROM logs
WHERE created_at > extract(epoch from now() - interval '{args.minutes} minutes')::bigint
{after_clause.rstrip()}
  AND token_id={args.token_id}
  AND channel_id={args.channel_id}
  AND model_name='{args.model}'
ORDER BY id DESC
LIMIT 80;
"""
    cmd = [
        "docker",
        "exec",
        "-i",
        "newapi-postgres",
        "psql",
        "-U",
        "newapi",
        "-d",
        "newapi",
        "-At",
        "-F",
        "\t",
    ]
    proc = subprocess.run(
        cmd,
        input=query,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())

    rows: list[LogRow] = []
    for line in proc.stdout.splitlines():
        if not line or line == "SET":
            continue
        parts = line.split("\t")
        if len(parts) != 8:
            continue
        rows.append(
            LogRow(
                id=int(parts[0]),
                created_epoch=int(parts[1]),
                created_at=parts[2],
                token_id=int(parts[3]),
                channel_id=int(parts[4]),
                prompt_tokens=int(parts[5] or 0),
                completion_tokens=int(parts[6] or 0),
                request_id=parts[7],
            )
        )
    return rows


def parse_iso_local(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(dt.datetime.fromisoformat(value).timestamp())
    except ValueError:
        return None


def tap_files(args: argparse.Namespace, logs: list[LogRow]) -> list[str]:
    if args.date:
        date_folder = args.date
    elif logs:
        date_folder = dt.datetime.fromtimestamp(logs[0].created_epoch, dt.UTC).strftime("%Y%m%d")
    else:
        date_folder = dt.datetime.now().strftime("%Y%m%d")

    if not logs:
        hour_glob = os.path.join(args.tap_root, date_folder, "*", "records", "*.json")
        return glob.glob(hour_glob)

    hours: set[str] = set()
    for row in logs:
        base = dt.datetime.fromtimestamp(row.created_epoch, dt.UTC)
        for offset in (-1, 0, 1):
            hours.add((base + dt.timedelta(hours=offset)).strftime("%H"))

    files: list[str] = []
    for hour in sorted(hours):
        files.extend(glob.glob(os.path.join(args.tap_root, date_folder, hour, "records", "*.json")))
    return files


def metadata_session_id(request_body: dict[str, Any]) -> str:
    metadata = request_body.get("metadata") or {}
    raw_user_id = metadata.get("user_id")
    if not isinstance(raw_user_id, str):
        return ""
    try:
        parsed = json.loads(raw_user_id)
    except json.JSONDecodeError:
        return ""
    value = parsed.get("session_id")
    return value if isinstance(value, str) else ""


def classify_request(request_body: dict[str, Any]) -> str:
    raw = json.dumps(request_body, ensure_ascii=False)
    for marker, label in MARKERS:
        if marker in raw:
            return label
    return "unknown"


def parse_stream_response(response_body: str) -> dict[str, Any]:
    event_types: list[str] = []
    content_block_types: list[str] = []
    signature_delta_count = 0
    thinking_delta_count = 0
    text_preview = ""
    stop_reason = ""

    for line in response_body.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            continue
        event_type = event.get("type")
        if isinstance(event_type, str):
            event_types.append(event_type)
        if event_type == "content_block_start":
            block_type = (event.get("content_block") or {}).get("type")
            content_block_types.append(block_type)
        elif event_type == "content_block_delta":
            delta = event.get("delta") or {}
            delta_type = delta.get("type")
            if delta_type == "signature_delta":
                signature_delta_count += 1
            elif delta_type == "thinking_delta":
                thinking_delta_count += 1
            elif delta_type == "text_delta" and len(text_preview) < 160:
                text_preview += str(delta.get("text", ""))[: 160 - len(text_preview)]
        elif event_type == "message_delta":
            stop_reason = (event.get("delta") or {}).get("stop_reason") or stop_reason

    return {
        "response_kind": "stream",
        "event_counts": dict(Counter(event_types)),
        "content_block_types": content_block_types,
        "signature_delta_count": signature_delta_count,
        "thinking_delta_count": thinking_delta_count,
        "stop_reason": stop_reason,
        "text_preview": text_preview.replace("\n", " ")[:160],
    }


def parse_json_response(response_body: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(response_body, str):
        parsed = json.loads(response_body)
    else:
        parsed = response_body

    content = parsed.get("content") or []
    content_types: list[str] = []
    text_preview = ""
    for block in content:
        if not isinstance(block, dict):
            continue
        content_types.append(str(block.get("type")))
        if block.get("type") == "text" and len(text_preview) < 160:
            text_preview += str(block.get("text", ""))[: 160 - len(text_preview)]

    return {
        "response_kind": "json",
        "content_types": content_types,
        "stop_reason": parsed.get("stop_reason"),
        "usage": parsed.get("usage"),
        "text_preview": text_preview.replace("\n", " ")[:160],
    }


def summarize_response(response_body: Any) -> dict[str, Any]:
    if isinstance(response_body, str) and "data:" in response_body:
        return parse_stream_response(response_body)
    try:
        return parse_json_response(response_body)
    except Exception as exc:  # noqa: BLE001 - diagnostics only
        return {"response_kind": "unparsed", "error": f"{type(exc).__name__}: {exc}"}


def load_candidate_records(args: argparse.Namespace, logs: list[LogRow]) -> list[dict[str, Any]]:
    if not logs:
        return []
    min_epoch = min(row.created_epoch for row in logs) - 180
    max_epoch = max(row.created_epoch for row in logs) + 180
    min_mtime = min_epoch - 600
    max_mtime = max_epoch + 600
    prompt_tokens = {row.prompt_tokens for row in logs if row.prompt_tokens}

    records: list[dict[str, Any]] = []
    for path in tap_files(args, logs):
        try:
            mtime = int(os.path.getmtime(path))
        except OSError:
            continue
        if mtime < min_mtime or mtime > max_mtime:
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        request_body = record.get("request_body") or {}
        if request_body.get("model") != args.model:
            continue
        created_epoch = parse_iso_local(record.get("created_at", ""))
        if created_epoch is None or created_epoch < min_epoch or created_epoch > max_epoch:
            continue
        record_prompt_tokens = record.get("prompt_tokens")
        if record_prompt_tokens not in prompt_tokens:
            continue
        session_id = metadata_session_id(request_body)
        if args.session_id and session_id != args.session_id:
            continue
        records.append(
            {
                "path": path,
                "created_at": record.get("created_at"),
                "created_epoch": created_epoch,
                "prompt_tokens": record_prompt_tokens,
                "session_id": session_id,
                "label": classify_request(request_body),
                "stream": request_body.get("stream"),
                "thinking": request_body.get("thinking"),
                "response": summarize_response(record.get("response_body")),
            }
        )
    return records


def select_session(records: list[dict[str, Any]], forced_session_id: str | None) -> str:
    if forced_session_id:
        return forced_session_id
    counts = Counter(record.get("session_id") for record in records if record.get("session_id"))
    if not counts:
        return ""
    newest_by_session = {
        session: max(
            int(record.get("created_epoch") or 0)
            for record in records
            if record.get("session_id") == session
        )
        for session in counts
    }
    return max(counts, key=lambda session: (counts[session], newest_by_session[session]))


def main() -> int:
    args = parse_args()
    logs = run_psql_logs(args)
    records = load_candidate_records(args, logs)
    session_id = select_session(records, args.session_id)
    if session_id:
        records = [record for record in records if record.get("session_id") == session_id]

    records.sort(key=lambda item: item["created_epoch"])
    summary = {
        "model": args.model,
        "token_id": args.token_id,
        "channel_id": args.channel_id,
        "log_rows": [row.__dict__ for row in logs],
        "selected_session_id": session_id,
        "tap_records": records,
    }

    output = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(output)
            handle.write("\n")
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
