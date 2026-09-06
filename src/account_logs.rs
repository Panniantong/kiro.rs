//! Per-credential structured log persistence and query support.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params_from_iter, types::Value, Connection, OpenFlags};
use serde::Serialize;
use serde_json::Value as JsonValue;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

const LOG_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
const WRITER_QUEUE_CAPACITY: usize = 4096;
const WRITER_BATCH_SIZE: usize = 100;
const MAX_MESSAGE_CHARS: usize = 512;

#[derive(Debug, Clone)]
pub struct AccountLogEvent {
    pub credential_id: u64,
    pub event_type: String,
    pub severity: String,
    pub outcome: String,
    pub model: Option<String>,
    pub api_type: Option<String>,
    pub error_class: Option<String>,
    pub upstream_status: Option<u16>,
    pub latency_ms: Option<u64>,
    pub request_id: Option<String>,
    pub message: String,
    pub details_json: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl AccountLogEvent {
    pub fn new(
        credential_id: u64,
        event_type: impl Into<String>,
        severity: impl Into<String>,
        outcome: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            credential_id,
            event_type: event_type.into(),
            severity: severity.into(),
            outcome: outcome.into(),
            model: None,
            api_type: None,
            error_class: None,
            upstream_status: None,
            latency_ms: None,
            request_id: None,
            message: message.into(),
            details_json: None,
            created_at: Utc::now(),
        }
    }

    fn sanitized(mut self) -> Self {
        self.message = truncate(&redact_sensitive_text(&self.message), MAX_MESSAGE_CHARS);
        self.model = self
            .model
            .map(|value| truncate(&redact_sensitive_text(&value), 128));
        self.api_type = self
            .api_type
            .map(|value| truncate(&redact_sensitive_text(&value), 64));
        self.error_class = self
            .error_class
            .map(|value| truncate(&redact_sensitive_text(&value), 128));
        self.request_id = self
            .request_id
            .map(|value| truncate(&redact_sensitive_text(&value), 128));
        self.details_json = self.details_json.and_then(|details| {
            serde_json::from_str::<JsonValue>(&details)
                .ok()
                .map(|mut value| {
                    redact_sensitive_json_value(&mut value);
                    value.to_string()
                })
        });
        self
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLogItem {
    pub id: u64,
    pub created_at: String,
    pub event_type: String,
    pub severity: String,
    pub outcome: String,
    pub model: Option<String>,
    pub api_type: Option<String>,
    pub error_class: Option<String>,
    pub upstream_status: Option<u16>,
    pub latency_ms: Option<u64>,
    pub request_id: Option<String>,
    pub message: String,
    pub details: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLogPage {
    pub items: Vec<AccountLogItem>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AccountLogFilters {
    pub severity: Option<String>,
    pub event_type: Option<String>,
    pub outcome: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub before: Option<String>,
    pub limit: usize,
}

#[derive(Clone)]
pub struct AccountLogStore {
    path: PathBuf,
    sender: std::sync::mpsc::SyncSender<AccountLogEvent>,
}

impl AccountLogStore {
    pub fn open(cache_dir: Option<PathBuf>) -> anyhow::Result<Option<Arc<Self>>> {
        let Some(mut cache_dir) = cache_dir else {
            return Ok(None);
        };
        if cache_dir.as_os_str().is_empty() {
            cache_dir.push(".");
        }
        fs::create_dir_all(&cache_dir)?;
        let path = cache_dir.join("kiro_account_logs.sqlite");
        let connection = open_connection(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        initialize_schema(&connection)?;
        cleanup_old_logs(&connection)?;
        drop(connection);

        let (sender, receiver) = std::sync::mpsc::sync_channel(WRITER_QUEUE_CAPACITY);
        let writer_path = path.clone();
        thread::Builder::new()
            .name("kiro-account-log-writer".to_string())
            .spawn(move || writer_loop(writer_path, receiver))?;

        Ok(Some(Arc::new(Self { path, sender })))
    }

    pub fn record(&self, event: AccountLogEvent) -> anyhow::Result<()> {
        self.sender
            .send(event.sanitized())
            .map_err(|error| anyhow::anyhow!("账号日志写入队列已关闭: {error}"))
    }

    pub async fn query(
        &self,
        credential_id: u64,
        filters: AccountLogFilters,
    ) -> anyhow::Result<AccountLogPage> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || query_from_path(&path, credential_id, filters))
            .await
            .map_err(|error| anyhow::anyhow!("账号日志查询任务失败: {error}"))?
    }
}

fn open_connection(path: &PathBuf, flags: OpenFlags) -> rusqlite::Result<Connection> {
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;",
    )?;
    Ok(connection)
}

fn initialize_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS account_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            credential_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            outcome TEXT NOT NULL,
            model TEXT,
            api_type TEXT,
            error_class TEXT,
            upstream_status INTEGER,
            latency_ms INTEGER,
            request_id TEXT,
            message TEXT NOT NULL,
            details_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_account_logs_credential_time
            ON account_logs (credential_id, created_at DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_account_logs_time
            ON account_logs (created_at DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_account_logs_severity_time
            ON account_logs (severity, created_at DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_account_logs_event_time
            ON account_logs (event_type, created_at DESC, id DESC);",
    )?;
    Ok(())
}

fn cleanup_old_logs(connection: &Connection) -> rusqlite::Result<()> {
    let cutoff = Utc::now().timestamp_millis() - LOG_RETENTION_SECS * 1000;
    connection.execute("DELETE FROM account_logs WHERE created_at < ?1", [cutoff])?;
    Ok(())
}

fn writer_loop(path: PathBuf, receiver: std::sync::mpsc::Receiver<AccountLogEvent>) {
    let connection = match open_connection(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .and_then(|connection| initialize_schema(&connection).map(|_| connection))
    {
        Ok(connection) => connection,
        Err(error) => {
            tracing::error!(target: "account_logs", error = %error, "账号日志数据库打开失败");
            return;
        }
    };

    loop {
        let first = match receiver.recv_timeout(Duration::from_secs(60)) {
            Ok(first) => first,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Err(error) = cleanup_old_logs(&connection) {
                    tracing::warn!(target: "account_logs", error = %error, "账号日志保留期清理失败");
                }
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let mut batch = Vec::with_capacity(WRITER_BATCH_SIZE);
        batch.push(first);
        while batch.len() < WRITER_BATCH_SIZE {
            match receiver.try_recv() {
                Ok(event) => batch.push(event),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }

        let transaction = match connection.unchecked_transaction() {
            Ok(transaction) => transaction,
            Err(error) => {
                tracing::error!(target: "account_logs", error = %error, "账号日志事务开启失败");
                continue;
            }
        };
        let insert_result = {
            let mut statement = match transaction.prepare(
                "INSERT INTO account_logs (
                    created_at, credential_id, event_type, severity, outcome,
                    model, api_type, error_class, upstream_status, latency_ms,
                    request_id, message, details_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            ) {
                Ok(statement) => statement,
                Err(error) => {
                    tracing::error!(target: "account_logs", error = %error, "账号日志插入语句准备失败");
                    continue;
                }
            };
            batch.iter().try_for_each(|event| {
                statement
                    .execute((
                        event.created_at.timestamp_millis(),
                        event.credential_id as i64,
                        &event.event_type,
                        &event.severity,
                        &event.outcome,
                        event.model.as_deref(),
                        event.api_type.as_deref(),
                        event.error_class.as_deref(),
                        event.upstream_status.map(i64::from),
                        event.latency_ms.map(|value| value as i64),
                        event.request_id.as_deref(),
                        &event.message,
                        event.details_json.as_deref(),
                    ))
                    .map(|_| ())
            })
        };

        if let Err(error) = insert_result {
            tracing::error!(target: "account_logs", error = %error, "账号日志批量写入失败");
            continue;
        }
        if let Err(error) = transaction.commit() {
            tracing::error!(target: "account_logs", error = %error, "账号日志事务提交失败");
        }
    }
}

fn query_from_path(
    path: &PathBuf,
    credential_id: u64,
    filters: AccountLogFilters,
) -> anyhow::Result<AccountLogPage> {
    let connection = open_connection(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    let mut conditions = vec!["credential_id = ?".to_string()];
    let mut values = vec![Value::Integer(credential_id as i64)];

    if let Some(severity) = filters.severity {
        conditions.push("severity = ?".to_string());
        values.push(Value::Text(severity));
    }
    if let Some(event_type) = filters.event_type {
        conditions.push("event_type = ?".to_string());
        values.push(Value::Text(event_type));
    }
    if let Some(outcome) = filters.outcome {
        conditions.push("outcome = ?".to_string());
        values.push(Value::Text(outcome));
    }
    if let Some(from_ms) = filters.from_ms {
        conditions.push("created_at >= ?".to_string());
        values.push(Value::Integer(from_ms));
    }
    if let Some(to_ms) = filters.to_ms {
        conditions.push("created_at <= ?".to_string());
        values.push(Value::Integer(to_ms));
    }
    if let Some(before) = filters.before.as_deref() {
        let before = decode_cursor(before).ok_or_else(|| anyhow::anyhow!("无效的日志分页游标"))?;
        conditions.push("(created_at < ? OR (created_at = ? AND id < ?))".to_string());
        values.push(Value::Integer(before.0));
        values.push(Value::Integer(before.0));
        values.push(Value::Integer(before.1));
    }

    let limit = filters.limit.clamp(1, 100);
    let sql = format!(
        "SELECT id, created_at, event_type, severity, outcome, model, api_type,
                error_class, upstream_status, latency_ms, request_id, message, details_json
         FROM account_logs WHERE {} ORDER BY created_at DESC, id DESC LIMIT ?",
        conditions.join(" AND ")
    );
    values.push(Value::Integer((limit + 1) as i64));

    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(params_from_iter(values))?;
    let mut raw_items = Vec::with_capacity(limit + 1);
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let created_at_ms: i64 = row.get(1)?;
        raw_items.push((
            id,
            created_at_ms,
            AccountLogItem {
                id: id as u64,
                created_at: DateTime::<Utc>::from_timestamp_millis(created_at_ms)
                    .map(|date| date.to_rfc3339())
                    .unwrap_or_else(|| "1970-01-01T00:00:00+00:00".to_string()),
                event_type: row.get(2)?,
                severity: row.get(3)?,
                outcome: row.get(4)?,
                model: row.get(5)?,
                api_type: row.get(6)?,
                error_class: row.get(7)?,
                upstream_status: row.get::<_, Option<i64>>(8)?.map(|value| value as u16),
                latency_ms: row.get::<_, Option<i64>>(9)?.map(|value| value as u64),
                request_id: row.get(10)?,
                message: row.get(11)?,
                details: row
                    .get::<_, Option<String>>(12)?
                    .and_then(|value| serde_json::from_str(&value).ok()),
            },
        ));
    }

    let has_more = raw_items.len() > limit;
    raw_items.truncate(limit);
    let next_cursor = if has_more {
        raw_items
            .last()
            .map(|(id, created_at_ms, _)| encode_cursor(*created_at_ms, *id))
    } else {
        None
    };
    Ok(AccountLogPage {
        items: raw_items.into_iter().map(|(_, _, item)| item).collect(),
        next_cursor,
        has_more,
    })
}

fn encode_cursor(created_at_ms: i64, id: i64) -> String {
    URL_SAFE_NO_PAD.encode(format!("{created_at_ms}:{id}"))
}

fn decode_cursor(value: &str) -> Option<(i64, i64)> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (created_at, id) = text.split_once(':')?;
    Some((created_at.parse().ok()?, id.parse().ok()?))
}

#[derive(Default)]
pub struct AccountLogLayer;

static GLOBAL_STORE: OnceLock<Mutex<Option<Arc<AccountLogStore>>>> = OnceLock::new();

pub fn set_global_store(store: Arc<AccountLogStore>) {
    *GLOBAL_STORE.get_or_init(|| Mutex::new(None)).lock() = Some(store);
}

fn global_store() -> Option<Arc<AccountLogStore>> {
    GLOBAL_STORE
        .get()
        .and_then(|slot| slot.lock().as_ref().cloned())
}

impl<S> Layer<S> for AccountLogLayer
where
    S: tracing::Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let Some(store) = global_store() else {
            return;
        };
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let Some(credential_id) = visitor.credential_id() else {
            return;
        };
        let event = visitor.into_event(credential_id, event.metadata().level().as_str());
        if let Err(error) = store.record(event) {
            tracing::warn!(target: "account_logs", error = %error, "账号日志事件入队失败");
        }
    }
}

#[derive(Default)]
struct EventVisitor {
    values: HashMap<String, String>,
}

impl EventVisitor {
    fn credential_id(&self) -> Option<u64> {
        if self
            .values
            .get("credential_id_present")
            .map(|value| value == "false")
            .unwrap_or(false)
        {
            return None;
        }
        let id = self.values.get("credential_id")?.parse::<u64>().ok()?;
        (id > 0).then_some(id)
    }

    fn into_event(self, credential_id: u64, level: &str) -> AccountLogEvent {
        let message = self.values.get("message").cloned().unwrap_or_default();
        let event_type = self
            .values
            .get("event_type")
            .cloned()
            .filter(|value| is_known_event_type(value))
            .unwrap_or_else(|| infer_event_type(&self.values, &message));
        let outcome = infer_outcome(&self.values, &message, level);
        let severity = level.to_ascii_lowercase();
        let mut event = AccountLogEvent::new(credential_id, event_type, severity, outcome, message);
        event.model = self.values.get("model").cloned();
        event.api_type = self.values.get("api_type").cloned();
        event.error_class = self.values.get("error_class").cloned();
        event.upstream_status = self
            .values
            .get("upstream_status")
            .and_then(|value| value.parse::<u16>().ok());
        event.latency_ms = self
            .values
            .get("ttfb_ms")
            .or_else(|| self.values.get("elapsed_ms"))
            .and_then(|value| value.parse::<u64>().ok());
        event.request_id = self.values.get("request_id").cloned();

        let detail_keys = [
            "attempt",
            "max_retries",
            "retry_after_secs",
            "request_outcome",
            "credential_id_present",
            "upstream_status_present",
            "retry_after_present",
            "permanently_invalid",
            "auth_method",
        ];
        let details: serde_json::Map<String, JsonValue> = detail_keys
            .into_iter()
            .filter_map(|key| {
                self.values
                    .get(key)
                    .map(|value| (key.to_string(), JsonValue::String(value.clone())))
            })
            .collect();
        if !details.is_empty() {
            event.details_json = Some(JsonValue::Object(details).to_string());
        }
        event
    }
}

impl tracing::field::Visit for EventVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.values.insert(
            field.name().to_string(),
            normalize_debug(&format!("{value:?}")),
        );
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.values
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.values
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.values
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.values
            .insert(field.name().to_string(), value.to_string());
    }
}

fn normalize_debug(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

fn is_known_event_type(value: &str) -> bool {
    matches!(
        value,
        "request" | "token_refresh" | "balance" | "credential_status" | "proxy" | "recovery_probe"
    )
}

fn infer_event_type(values: &HashMap<String, String>, message: &str) -> String {
    let lowered = message.to_ascii_lowercase();
    if values.contains_key("request_outcome")
        || values.contains_key("model")
        || values.contains_key("api_type")
    {
        "request".to_string()
    } else if lowered.contains("token") || lowered.contains("刷新") {
        "token_refresh".to_string()
    } else if lowered.contains("余额") || lowered.contains("额度") || lowered.contains("quota")
    {
        "balance".to_string()
    } else if message.contains("代理") {
        "proxy".to_string()
    } else if message.contains("探针") || message.contains("恢复") {
        "recovery_probe".to_string()
    } else {
        "credential_status".to_string()
    }
}

fn infer_outcome(values: &HashMap<String, String>, message: &str, level: &str) -> String {
    if let Some(value) = values.get("request_outcome") {
        if value == "success" {
            return "success".to_string();
        }
        if value.contains("pending") {
            return "pending".to_string();
        }
        return "failure".to_string();
    }
    if message.contains("重试") {
        return "retry".to_string();
    }
    if message.contains("成功") || message.contains("完成") {
        return "success".to_string();
    }
    if level.eq_ignore_ascii_case("error") || level.eq_ignore_ascii_case("warn") {
        return "failure".to_string();
    }
    "pending".to_string()
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn redact_sensitive_text(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if let Ok(mut json) = serde_json::from_str::<JsonValue>(value) {
        redact_sensitive_json_value(&mut json);
        return json.to_string();
    }
    let lowered = value.to_ascii_lowercase();
    let sensitive_markers = [
        "authorization:",
        "authorization=",
        "bearer ",
        "refresh_token",
        "refresh-token",
        "refreshtoken",
        "access_token",
        "access-token",
        "accesstoken",
        "client_secret",
        "client-secret",
        "clientsecret",
        "api_key",
        "api-key",
        "apikey",
        "cookie:",
        "cookie=",
        "set-cookie",
        "proxy_password",
        "proxy-password",
        "password=",
        "secret=",
    ];
    if sensitive_markers
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        "[REDACTED_SENSITIVE_LOG]".to_string()
    } else {
        value.to_string()
    }
}

fn redact_sensitive_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::Object(map) => {
            for (key, child) in map.iter_mut() {
                let lowered = key.to_ascii_lowercase();
                if [
                    "authorization",
                    "cookie",
                    "set-cookie",
                    "refresh_token",
                    "refresh-token",
                    "access_token",
                    "access-token",
                    "id_token",
                    "client_secret",
                    "client-secret",
                    "api_key",
                    "api-key",
                    "password",
                    "secret",
                ]
                .iter()
                .any(|needle| lowered.contains(needle))
                {
                    *child = JsonValue::String("[REDACTED]".to_string());
                } else {
                    redact_sensitive_json_value(child);
                }
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                redact_sensitive_json_value(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_is_stable() {
        let encoded = encode_cursor(123456789, 42);
        assert_eq!(decode_cursor(&encoded), Some((123456789, 42)));
    }

    #[test]
    fn sensitive_event_details_are_redacted() {
        let event = AccountLogEvent {
            details_json: Some(r#"{"authorization":"Bearer secret","attempt":2}"#.to_string()),
            ..AccountLogEvent::new(1, "request", "error", "failure", "upstream failed")
        }
        .sanitized();
        assert_eq!(
            serde_json::from_str::<JsonValue>(event.details_json.as_deref().unwrap()).unwrap(),
            serde_json::json!({"authorization": "[REDACTED]", "attempt": 2})
        );
        assert_eq!(
            redact_sensitive_text("refreshToken=secret"),
            "[REDACTED_SENSITIVE_LOG]"
        );
    }

    #[test]
    fn event_visitor_skips_unattributed_events() {
        let mut visitor = EventVisitor::default();
        visitor
            .values
            .insert("credential_id".to_string(), "0".to_string());
        visitor
            .values
            .insert("credential_id_present".to_string(), "false".to_string());

        assert_eq!(visitor.credential_id(), None);
    }

    #[test]
    fn cleanup_removes_logs_older_than_retention_window() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "kiro-account-logs-retention-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("logs.sqlite");
        let connection = open_connection(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .expect("open sqlite");
        initialize_schema(&connection).expect("create schema");
        let now = Utc::now().timestamp_millis();
        let old = now - LOG_RETENTION_SECS * 1000 - 1;
        connection
            .execute(
                "INSERT INTO account_logs
                    (created_at, credential_id, event_type, severity, outcome, message)
                 VALUES (?1, 1, 'request', 'info', 'success', 'old')",
                [old],
            )
            .expect("insert old event");
        connection
            .execute(
                "INSERT INTO account_logs
                    (created_at, credential_id, event_type, severity, outcome, message)
                 VALUES (?1, 1, 'request', 'info', 'success', 'new')",
                [now],
            )
            .expect("insert current event");
        cleanup_old_logs(&connection).expect("cleanup old events");
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM account_logs", [], |row| row.get(0))
            .expect("count retained events");
        assert_eq!(count, 1);
        drop(connection);
        let _ = fs::remove_dir_all(dir);
    }
    #[tokio::test]
    async fn store_queries_are_isolated_and_cursor_paginated() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "kiro-account-logs-test-{}-{suffix}",
            std::process::id()
        ));
        let store = AccountLogStore::open(Some(dir.clone()))
            .expect("open store")
            .expect("store should be enabled");

        for index in 0..105 {
            let mut event = AccountLogEvent::new(
                7,
                "request",
                if index % 2 == 0 { "error" } else { "info" },
                "failure",
                format!("request {index}"),
            );
            event.created_at = Utc::now() + chrono::Duration::milliseconds(index);
            store.record(event).expect("enqueue event");
        }

        let mut page = None;
        for _ in 0..20 {
            let candidate = store
                .query(
                    7,
                    AccountLogFilters {
                        limit: 100,
                        ..Default::default()
                    },
                )
                .await
                .expect("query first page");
            if candidate.items.len() == 100 && candidate.has_more {
                page = Some(candidate);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let page = page.expect("writer should flush all events");
        assert_eq!(page.items.len(), 100);
        assert!(page.has_more);
        assert!(page.next_cursor.is_some());

        let next_page = store
            .query(
                7,
                AccountLogFilters {
                    before: page.next_cursor.clone(),
                    limit: 100,
                    ..Default::default()
                },
            )
            .await
            .expect("query next page");
        assert_eq!(next_page.items.len(), 5);
        assert!(!next_page.has_more);

        let error_page = store
            .query(
                7,
                AccountLogFilters {
                    severity: Some("error".to_string()),
                    limit: 100,
                    ..Default::default()
                },
            )
            .await
            .expect("query filtered page");
        assert_eq!(error_page.items.len(), 53);

        let other_account_page = store
            .query(
                8,
                AccountLogFilters {
                    limit: 100,
                    ..Default::default()
                },
            )
            .await
            .expect("query other account");
        assert!(other_account_page.items.is_empty());

        drop(store);
        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = fs::remove_dir_all(dir);
    }
}
