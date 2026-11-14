//! 客户提示词审核拦截记录存储与查询
//!
//! 关口每判出一条违规（`block` 拦截 / `log` 只记）或判官出错、超时就追加一条记录，
//! 落到 `cache_dir/prompt_guard_events.sqlite`；判为 Pass 不记。存储是附加能力：
//! 写入失败只 warn，不影响请求；查询走 Admin API 只读暴露。
//!
//! 保留期 90 天：每次插入顺手删掉过期记录（写入量很小，不需要后台线程）。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags, params_from_iter, types::Value};
use serde::Serialize;

/// block 模式判为违规、请求被 400 拒绝。
pub const KIND_BLOCK: &str = "block";
/// log 模式判为违规（未拦截）。
pub const KIND_LOG_ONLY: &str = "log_only";
/// 判官出错 / 超时（照常放行）。
pub const KIND_JUDGE_ERROR: &str = "judge_error";

/// 记录保留期（秒）。
const RETENTION_SECS: i64 = 90 * 24 * 60 * 60;
/// 违规记录里保留的客户被审文本字符数（按字符截，保留换行）。
const PREVIEW_CHARS: usize = 2000;
/// judge_error 记录里错误字符串的字符数上限。
const REASON_CHARS: usize = 300;
/// 单页最大条数。
const MAX_PAGE_SIZE: u64 = 100;

/// 一条待写入的拦截记录。
#[derive(Debug, Clone)]
pub struct PromptGuardEvent {
    /// 毫秒时间戳
    pub created_at_ms: i64,
    /// `block` / `log_only` / `judge_error`
    pub kind: String,
    pub category: String,
    pub reason: String,
    pub model: String,
    pub path: String,
    /// `block` 拦截为 400，其余为空
    pub status: Option<u16>,
    pub elapsed_ms: i64,
    /// 被审文本字符数
    pub chars: i64,
    /// 超长只送审了头尾
    pub truncated: bool,
    /// 违规时为客户被审文本前 2000 字；judge_error 为空串
    pub preview: String,
}

impl PromptGuardEvent {
    /// 违规记录：`kind` 为 [`KIND_BLOCK`]（`status` 传 400）或 [`KIND_LOG_ONLY`]（`status` 为 None）。
    pub fn violation(
        kind: &str,
        category: &str,
        reason: &str,
        model: &str,
        path: &str,
        status: Option<u16>,
        elapsed_ms: u64,
        chars: usize,
        truncated: bool,
        text: &str,
    ) -> Self {
        Self {
            created_at_ms: Utc::now().timestamp_millis(),
            kind: kind.to_string(),
            category: category.to_string(),
            reason: reason.to_string(),
            model: model.to_string(),
            path: path.to_string(),
            status,
            elapsed_ms: elapsed_ms as i64,
            chars: chars as i64,
            truncated,
            preview: truncate_chars(text, PREVIEW_CHARS),
        }
    }

    /// 判官出错 / 超时记录：不保留客户内容（preview 为空串）。
    pub fn judge_error(
        error: &str,
        model: &str,
        path: &str,
        elapsed_ms: u64,
        chars: usize,
        truncated: bool,
    ) -> Self {
        Self {
            created_at_ms: Utc::now().timestamp_millis(),
            kind: KIND_JUDGE_ERROR.to_string(),
            category: String::new(),
            reason: truncate_chars(error, REASON_CHARS),
            model: model.to_string(),
            path: path.to_string(),
            status: None,
            elapsed_ms: elapsed_ms as i64,
            chars: chars as i64,
            truncated,
            preview: String::new(),
        }
    }
}

/// 查询过滤条件。
#[derive(Debug, Clone, Default)]
pub struct PromptGuardEventFilters {
    /// 天数（1 / 7 / 30）；0 或负数 = 全部时间
    pub days: i64,
    pub kind: Option<String>,
    pub category: Option<String>,
    /// 从 1 开始
    pub page: u64,
    pub page_size: u64,
}

/// 三条计数（只按 days 过滤）。
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptGuardEventTotals {
    pub block: u64,
    pub log_only: u64,
    pub judge_error: u64,
}

/// 某类别的违规条数。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptGuardCategoryCount {
    pub category: String,
    pub count: u64,
}

/// 单条记录。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptGuardEventItem {
    pub id: u64,
    /// RFC3339 UTC
    pub created_at: String,
    pub kind: String,
    pub category: String,
    pub reason: String,
    pub model: String,
    pub path: String,
    pub status: Option<u16>,
    pub elapsed_ms: i64,
    pub chars: i64,
    pub truncated: bool,
    pub preview: String,
}

/// 一次查询的全部结果。
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptGuardEventReport {
    pub totals: PromptGuardEventTotals,
    pub categories: Vec<PromptGuardCategoryCount>,
    pub recent_judge_errors_1h: u64,
    pub items: Vec<PromptGuardEventItem>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

/// 拦截记录存储
#[derive(Clone)]
pub struct PromptGuardEventStore {
    path: PathBuf,
}

impl PromptGuardEventStore {
    /// 打开存储；`cache_dir` 为 None 时返回 `Ok(None)`（未配置缓存目录 = 不启用）。
    pub fn open(cache_dir: Option<PathBuf>) -> anyhow::Result<Option<Arc<Self>>> {
        let Some(mut cache_dir) = cache_dir else {
            return Ok(None);
        };
        if cache_dir.as_os_str().is_empty() {
            cache_dir.push(".");
        }
        fs::create_dir_all(&cache_dir)?;
        let path = cache_dir.join("prompt_guard_events.sqlite");
        let connection = open_connection(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        initialize_schema(&connection)?;
        cleanup_old_events(&connection, Utc::now().timestamp_millis())?;
        Ok(Some(Arc::new(Self { path })))
    }

    /// 追加一条记录。写入很少，直接 `spawn_blocking` 建连插入；失败只 warn，不影响请求。
    pub fn record(&self, event: PromptGuardEvent) {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(error) = insert_event(&path, &event, Utc::now().timestamp_millis()) {
                tracing::warn!(target: "prompt_guard", error = %error, "拦截记录写入失败");
            }
        });
    }

    /// 查询拦截记录（走 `spawn_blocking`）。
    pub async fn query(
        &self,
        filters: PromptGuardEventFilters,
    ) -> anyhow::Result<PromptGuardEventReport> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            query_from_path(&path, filters, Utc::now().timestamp_millis())
        })
        .await
        .map_err(|error| anyhow::anyhow!("拦截记录查询任务失败: {error}"))?
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
        "CREATE TABLE IF NOT EXISTS prompt_guard_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            kind TEXT NOT NULL,
            category TEXT NOT NULL,
            reason TEXT NOT NULL,
            model TEXT NOT NULL,
            path TEXT NOT NULL,
            status INTEGER,
            elapsed_ms INTEGER NOT NULL,
            chars INTEGER NOT NULL,
            truncated INTEGER NOT NULL,
            preview TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_prompt_guard_events_time
            ON prompt_guard_events (created_at DESC, id DESC);",
    )?;
    Ok(())
}

fn cleanup_old_events(connection: &Connection, now_ms: i64) -> rusqlite::Result<()> {
    connection.execute(
        "DELETE FROM prompt_guard_events WHERE created_at < ?1",
        [now_ms - RETENTION_SECS * 1000],
    )?;
    Ok(())
}

/// 插入一条记录并顺手清理过期记录。
fn insert_event(path: &PathBuf, event: &PromptGuardEvent, now_ms: i64) -> anyhow::Result<()> {
    let connection = open_connection(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )?;
    connection.execute(
        "INSERT INTO prompt_guard_events (
            created_at, kind, category, reason, model, path, status, elapsed_ms,
            chars, truncated, preview
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            event.created_at_ms,
            event.kind,
            event.category,
            event.reason,
            event.model,
            event.path,
            event.status.map(i64::from),
            event.elapsed_ms,
            event.chars,
            event.truncated as i64,
            event.preview,
        ],
    )?;
    cleanup_old_events(&connection, now_ms)?;
    Ok(())
}

/// `days` 转时间下限；0 或负数表示不限时间。
fn days_cutoff(days: i64, now_ms: i64) -> Option<i64> {
    if days <= 0 {
        None
    } else {
        Some(now_ms.saturating_sub(days.saturating_mul(24 * 60 * 60 * 1000)))
    }
}

fn ms_to_rfc3339(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|date| date.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00+00:00".to_string())
}

fn query_from_path(
    path: &PathBuf,
    filters: PromptGuardEventFilters,
    now_ms: i64,
) -> anyhow::Result<PromptGuardEventReport> {
    let connection = open_connection(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    let cutoff = days_cutoff(filters.days, now_ms);

    // 计数与类别分布只按 days 过滤：时间窗口是全量概览，不跟随 kind / category 筛选。
    let mut totals = PromptGuardEventTotals::default();
    {
        let mut statement = connection.prepare(
            "SELECT kind, COUNT(*) FROM prompt_guard_events
             WHERE (?1 IS NULL OR created_at >= ?1)
             GROUP BY kind",
        )?;
        let rows = statement.query_map([cutoff], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (kind, count) = row?;
            let count = count.max(0) as u64;
            match kind.as_str() {
                KIND_BLOCK => totals.block = count,
                KIND_LOG_ONLY => totals.log_only = count,
                KIND_JUDGE_ERROR => totals.judge_error = count,
                _ => {}
            }
        }
    }

    let mut categories = Vec::new();
    {
        let mut statement = connection.prepare(
            "SELECT category, COUNT(*) AS total FROM prompt_guard_events
             WHERE kind IN (?1, ?2) AND (?3 IS NULL OR created_at >= ?3)
             GROUP BY category
             ORDER BY total DESC, category ASC",
        )?;
        let rows = statement.query_map(
            rusqlite::params![KIND_BLOCK, KIND_LOG_ONLY, cutoff],
            |row| {
                Ok(PromptGuardCategoryCount {
                    category: row.get(0)?,
                    count: row.get::<_, i64>(1)?.max(0) as u64,
                })
            },
        )?;
        for row in rows {
            categories.push(row?);
        }
    }

    let recent_judge_errors_1h: u64 = connection.query_row(
        "SELECT COUNT(*) FROM prompt_guard_events
         WHERE kind = ?1 AND created_at >= ?2",
        rusqlite::params![KIND_JUDGE_ERROR, now_ms - 60 * 60 * 1000],
        |row| row.get::<_, i64>(0),
    )? as u64;

    let mut conditions: Vec<String> = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    if let Some(cutoff) = cutoff {
        conditions.push("created_at >= ?".to_string());
        values.push(Value::Integer(cutoff));
    }
    if let Some(kind) = filters.kind.as_deref().filter(|value| !value.is_empty()) {
        conditions.push("kind = ?".to_string());
        values.push(Value::Text(kind.to_string()));
    }
    if let Some(category) = filters.category.as_deref().filter(|value| !value.is_empty()) {
        conditions.push("category = ?".to_string());
        values.push(Value::Text(category.to_string()));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let total: u64 = connection.query_row(
        &format!("SELECT COUNT(*) FROM prompt_guard_events{where_clause}"),
        params_from_iter(values.iter()),
        |row| row.get::<_, i64>(0),
    )? as u64;

    let page = filters.page.clamp(1, i64::MAX as u64 / MAX_PAGE_SIZE);
    let page_size = filters.page_size.clamp(1, MAX_PAGE_SIZE);
    let mut page_values = values;
    page_values.push(Value::Integer(page_size as i64));
    page_values.push(Value::Integer(((page - 1) * page_size) as i64));

    let mut items = Vec::new();
    {
        let mut statement = connection.prepare(&format!(
            "SELECT id, created_at, kind, category, reason, model, path, status,
                    elapsed_ms, chars, truncated, preview
             FROM prompt_guard_events{where_clause}
             ORDER BY created_at DESC, id DESC
             LIMIT ? OFFSET ?"
        ))?;
        let rows = statement.query_map(params_from_iter(page_values.iter()), |row| {
            let created_at_ms: i64 = row.get(1)?;
            Ok(PromptGuardEventItem {
                id: row.get::<_, i64>(0)?.max(0) as u64,
                created_at: ms_to_rfc3339(created_at_ms),
                kind: row.get(2)?,
                category: row.get(3)?,
                reason: row.get(4)?,
                model: row.get(5)?,
                path: row.get(6)?,
                status: row.get::<_, Option<i64>>(7)?.map(|value| value as u16),
                elapsed_ms: row.get(8)?,
                chars: row.get(9)?,
                truncated: row.get::<_, i64>(10)? != 0,
                preview: row.get(11)?,
            })
        })?;
        for row in rows {
            items.push(row?);
        }
    }

    Ok(PromptGuardEventReport {
        totals,
        categories,
        recent_judge_errors_1h,
        items,
        total,
        page,
        page_size,
    })
}

fn truncate_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    /// 唯一临时目录；Drop 时连同 sqlite 文件一起删除。
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let seq = TEMP_SEQ.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "kiro-pg-events-test-{}-{}-{}",
                std::process::id(),
                seq,
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn db_path(&self) -> PathBuf {
            self.path.join("prompt_guard_events.sqlite")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    const HOUR_MS: i64 = 60 * 60 * 1000;
    const DAY_MS: i64 = 24 * HOUR_MS;

    fn open_store(dir: &TempDir) -> Arc<PromptGuardEventStore> {
        PromptGuardEventStore::open(Some(dir.path.clone()))
            .unwrap()
            .expect("存储应已启用")
    }

    fn violation(kind: &str, category: &str, created_at_ms: i64, text: &str) -> PromptGuardEvent {
        let mut event = PromptGuardEvent::violation(
            kind,
            category,
            "测试原因",
            "glm-4.5-air",
            "/v1/messages",
            if kind == KIND_BLOCK { Some(400) } else { None },
            12,
            34,
            false,
            text,
        );
        event.created_at_ms = created_at_ms;
        event
    }

    fn insert(path: &PathBuf, event: &PromptGuardEvent, now_ms: i64) {
        insert_event(path, event, now_ms).unwrap();
    }

    fn filters(days: i64) -> PromptGuardEventFilters {
        PromptGuardEventFilters {
            days,
            page: 1,
            page_size: 20,
            ..Default::default()
        }
    }

    #[test]
    fn open_returns_none_without_cache_dir() {
        assert!(PromptGuardEventStore::open(None).unwrap().is_none());
    }

    #[test]
    fn totals_and_categories_only_follow_days() {
        let dir = TempDir::new();
        let _store = open_store(&dir);
        let path = dir.db_path();
        let now = Utc::now().timestamp_millis();

        insert(&path, &violation(KIND_BLOCK, "porn", now, "露骨内容"), now);
        insert(&path, &violation(KIND_BLOCK, "porn", now - 1, "露骨内容"), now);
        insert(&path, &violation(KIND_BLOCK, "intrusion", now - 2, "入侵"), now);
        insert(&path, &violation(KIND_LOG_ONLY, "jailbreak", now - 3, "越狱"), now);
        insert(&path, &violation(KIND_LOG_ONLY, "intrusion", now - 4, "入侵"), now);
        // 10 天前：days=7 时不应计入
        insert(
            &path,
            &violation(KIND_BLOCK, "porn", now - 10 * DAY_MS, "旧记录"),
            now,
        );
        let mut judge = PromptGuardEvent::judge_error("判官请求失败: 超时", "glm-4.5-air", "/v1/messages", 3000, 10, false);
        judge.created_at_ms = now - HOUR_MS / 2;
        insert(&path, &judge, now);
        // 2 小时前的判官错误：只算 totals，不算 1 小时计数
        let mut old_judge = judge.clone();
        old_judge.created_at_ms = now - 2 * HOUR_MS;
        insert(&path, &old_judge, now);

        let all = query_from_path(&path, filters(0), now).unwrap();
        assert_eq!(all.totals.block, 4);
        assert_eq!(all.totals.log_only, 2);
        assert_eq!(all.totals.judge_error, 2);
        assert_eq!(all.recent_judge_errors_1h, 1);
        assert_eq!(
            all.categories
                .iter()
                .map(|item| (item.category.as_str(), item.count))
                .collect::<Vec<_>>(),
            vec![("porn", 3), ("intrusion", 2), ("jailbreak", 1)],
        );

        let week = query_from_path(&path, filters(7), now).unwrap();
        assert_eq!(week.totals.block, 3);
        assert_eq!(week.totals.log_only, 2);
        assert_eq!(week.totals.judge_error, 2);
        assert_eq!(week.total, 7);
        assert_eq!(
            week.categories
                .iter()
                .map(|item| (item.category.as_str(), item.count))
                .collect::<Vec<_>>(),
            vec![("intrusion", 2), ("porn", 2), ("jailbreak", 1)],
        );
        // 计数不跟随 kind 筛选：即使只查 log_only，totals 仍是全量
        let log_only = query_from_path(
            &path,
            PromptGuardEventFilters {
                kind: Some(KIND_LOG_ONLY.to_string()),
                ..filters(7)
            },
            now,
        )
        .unwrap();
        assert_eq!(log_only.total, 2);
        assert_eq!(log_only.totals.block, 3);
        assert_eq!(log_only.totals.log_only, 2);
        assert!(log_only.items.iter().all(|item| item.kind == KIND_LOG_ONLY));
    }

    #[test]
    fn category_and_kind_filters_combine_and_paginate() {
        let dir = TempDir::new();
        let _store = open_store(&dir);
        let path = dir.db_path();
        let now = Utc::now().timestamp_millis();

        for index in 0..5 {
            insert(
                &path,
                &violation(KIND_BLOCK, "porn", now - index, &format!("第{}条", index)),
                now,
            );
        }
        insert(&path, &violation(KIND_BLOCK, "bio", now - 10, "生物"), now);
        insert(&path, &violation(KIND_LOG_ONLY, "porn", now - 11, "log 模式"), now);

        let page_one = query_from_path(
            &path,
            PromptGuardEventFilters {
                kind: Some(KIND_BLOCK.to_string()),
                category: Some("porn".to_string()),
                page: 1,
                page_size: 2,
                ..filters(0)
            },
            now,
        )
        .unwrap();
        assert_eq!(page_one.total, 5);
        assert_eq!(page_one.page, 1);
        assert_eq!(page_one.page_size, 2);
        assert_eq!(page_one.items.len(), 2);
        assert_eq!(page_one.items[0].preview, "第0条");
        assert_eq!(page_one.items[1].preview, "第1条");
        assert_eq!(page_one.items[0].status, Some(400));
        assert_eq!(page_one.items[0].path, "/v1/messages");
        assert!(!page_one.items[0].created_at.is_empty());

        let page_three = query_from_path(
            &path,
            PromptGuardEventFilters {
                kind: Some(KIND_BLOCK.to_string()),
                category: Some("porn".to_string()),
                page: 3,
                page_size: 2,
                ..filters(0)
            },
            now,
        )
        .unwrap();
        assert_eq!(page_three.total, 5);
        assert_eq!(page_three.items.len(), 1);
        assert_eq!(page_three.items[0].preview, "第4条");

        // 越界页返回空 items，但 total 不变
        let page_four = query_from_path(
            &path,
            PromptGuardEventFilters {
                kind: Some(KIND_BLOCK.to_string()),
                page: 4,
                page_size: 2,
                ..filters(0)
            },
            now,
        )
        .unwrap();
        assert!(page_four.items.is_empty());
        assert_eq!(page_four.total, 6);

        // pageSize 超过 100 被夹到 100
        let clamped = query_from_path(
            &path,
            PromptGuardEventFilters {
                page_size: 1000,
                ..filters(0)
            },
            now,
        )
        .unwrap();
        assert_eq!(clamped.page_size, 100);
    }

    #[test]
    fn judge_error_keeps_no_preview_and_truncates_reason() {
        let dir = TempDir::new();
        let _store = open_store(&dir);
        let path = dir.db_path();
        let now = Utc::now().timestamp_millis();

        let long_error = "错".repeat(500);
        let mut event = PromptGuardEvent::judge_error(&long_error, "glm-4.5-air", "/cc/v1/messages", 3001, 7, true);
        event.created_at_ms = now;
        insert(&path, &event, now);

        let report = query_from_path(&path, filters(0), now).unwrap();
        assert_eq!(report.items.len(), 1);
        let item = &report.items[0];
        assert_eq!(item.kind, KIND_JUDGE_ERROR);
        assert_eq!(item.category, "");
        assert_eq!(item.status, None);
        assert_eq!(item.reason.chars().count(), REASON_CHARS);
        assert_eq!(item.preview, "");
        assert!(item.truncated);
        assert_eq!(item.path, "/cc/v1/messages");
        assert_eq!(report.totals.judge_error, 1);
        assert!(report.categories.is_empty());
    }

    #[test]
    fn violation_preview_is_cut_to_2000_chars_keeping_newlines() {
        let text = format!("行一\n{}", "长".repeat(3000));
        let event = PromptGuardEvent::violation(
            KIND_BLOCK,
            "porn",
            "原因",
            "glm-4.5-air",
            "/v1/messages",
            Some(400),
            5,
            text.chars().count(),
            true,
            &text,
        );
        let preview = &event.preview;
        assert_eq!(preview.chars().count(), PREVIEW_CHARS);
        assert!(preview.starts_with("行一\n"));
        assert_eq!(event.category, "porn");
        assert_eq!(event.status, Some(400));
        assert!(event.truncated);
    }

    #[test]
    fn expired_events_are_purged_on_write() {
        let dir = TempDir::new();
        let _store = open_store(&dir);
        let path = dir.db_path();
        let now = Utc::now().timestamp_millis();

        // 91 天前的记录：插入后立刻被清理掉
        insert(
            &path,
            &violation(KIND_BLOCK, "porn", now - 91 * DAY_MS, "过期"),
            now,
        );
        let after_first = query_from_path(&path, filters(0), now).unwrap();
        assert_eq!(after_first.total, 0);

        // 89 天前的记录：仍在保留期内
        insert(
            &path,
            &violation(KIND_BLOCK, "porn", now - 89 * DAY_MS, "保留"),
            now,
        );
        let after_second = query_from_path(&path, filters(0), now).unwrap();
        assert_eq!(after_second.total, 1);
        assert_eq!(after_second.items[0].preview, "保留");

        // 直接调用清理：过期行被删除，未过期行保留
        let connection = open_connection(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .unwrap();
        connection
            .execute(
                "INSERT INTO prompt_guard_events (
                    created_at, kind, category, reason, model, path, status, elapsed_ms,
                    chars, truncated, preview
                 ) VALUES (?1, ?2, 'porn', 'r', 'm', '/v1/messages', NULL, 1, 1, 0, 'p')",
                rusqlite::params![now - 200 * DAY_MS, KIND_LOG_ONLY],
            )
            .unwrap();
        cleanup_old_events(&connection, now).unwrap();
        let remaining: i64 = connection
            .query_row("SELECT COUNT(*) FROM prompt_guard_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn report_serializes_documented_keys() {
        let report = PromptGuardEventReport {
            totals: PromptGuardEventTotals {
                block: 1,
                log_only: 2,
                judge_error: 3,
            },
            categories: vec![PromptGuardCategoryCount {
                category: "porn".to_string(),
                count: 3,
            }],
            recent_judge_errors_1h: 4,
            items: Vec::new(),
            total: 5,
            page: 1,
            page_size: 20,
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["totals"]["block"], 1);
        assert_eq!(value["totals"]["logOnly"], 2);
        assert_eq!(value["totals"]["judgeError"], 3);
        assert_eq!(value["recentJudgeErrors1h"], 4);
        assert_eq!(value["categories"][0]["category"], "porn");
        assert_eq!(value["categories"][0]["count"], 3);
        assert_eq!(value["pageSize"], 20);
        assert_eq!(value["total"], 5);
    }

    #[tokio::test]
    async fn record_writes_through_blocking_pool() {
        let dir = TempDir::new();
        let store = open_store(&dir);
        let path = dir.db_path();

        store.record(violation(KIND_BLOCK, "porn", Utc::now().timestamp_millis(), "写入"));

        // spawn_blocking 不保证立刻完成：轮询直到记录出现（最多 2 秒）。
        let mut items = Vec::new();
        for _ in 0..40 {
            items = query_from_path(&path, filters(0), Utc::now().timestamp_millis())
                .unwrap()
                .items;
            if !items.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].preview, "写入");
    }
}
