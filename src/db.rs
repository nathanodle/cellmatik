//! SQLite storage (spec §4): schema, migrations, all queries, retention
//! sweep, media file store. One writer behind an async Mutex; rusqlite
//! bundled; WAL. SECURITY (spec §7): prepared statements with bound
//! parameters only — no string-built SQL anywhere; ownership scoping in
//! WHERE clauses; media paths are generated ids, never input-derived.
//!
//! Schema deltas beyond the §4 listing (by design, reported at release):
//!  - `outbox.vp_deadline TEXT NOT NULL` — VP-decoded deadline.
//!  - `outbox.next_attempt_at TEXT` — retry-ladder pacing.
//!  - `inbox.fetch TEXT` — MMS fetch breadcrumb (ok|unfetchable).
//!  - `webhooks.failing/last_error/last_ok` — dispatcher state.
//!
//! Timestamps: fixed-width `%Y-%m-%dT%H:%M:%S%.3fZ` so SQL string
//! comparisons are chronologically correct.

use crate::types::*;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

fn now_ts() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn ts_minus(seconds: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(seconds.max(0)))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// RFC 3339 UTC timestamp `now + seconds` — the one deadline format
/// (lexicographically comparable, matches `now_ts`).
pub fn ts_plus(seconds: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(seconds.max(0)))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

fn ts_days_ago(days: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::days(days.max(0)))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS webhooks (
  client_id INTEGER PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  failing INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  last_ok TEXT
);
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY,
  client_id INTEGER NOT NULL REFERENCES clients(id),
  to_num TEXT NOT NULL,
  text TEXT NOT NULL,
  want_dr INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  submitted_at TEXT,
  delivered_at TEXT,
  error TEXT,
  vp_deadline TEXT NOT NULL,
  next_attempt_at TEXT
);
CREATE TABLE IF NOT EXISTS outbox_segments (
  outbox_id INTEGER NOT NULL REFERENCES outbox(id) ON DELETE CASCADE,
  seg_index INTEGER NOT NULL,
  mr INTEGER,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  delivered_at TEXT,
  PRIMARY KEY (outbox_id, seg_index)
);
CREATE TABLE IF NOT EXISTS inbox (
  id INTEGER PRIMARY KEY,
  sender TEXT NOT NULL,
  channel TEXT NOT NULL,
  text TEXT NOT NULL DEFAULT '',
  fetch TEXT,
  received_at TEXT NOT NULL,
  read INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS media (
  id INTEGER PRIMARY KEY,
  inbox_id INTEGER REFERENCES inbox(id) ON DELETE CASCADE,
  mms_outbox_id INTEGER,
  name TEXT NOT NULL,
  content_type TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  path TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mms_outbox (
  id INTEGER PRIMARY KEY,
  client_id INTEGER NOT NULL REFERENCES clients(id),
  to_num TEXT NOT NULL,
  text TEXT,
  media_id INTEGER NOT NULL REFERENCES media(id),
  status TEXT NOT NULL DEFAULT 'queued',
  error TEXT,
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE TABLE IF NOT EXISTS calls (
  id INTEGER PRIMARY KEY,
  client_id INTEGER NOT NULL REFERENCES clients(id),
  direction TEXT NOT NULL,
  remote TEXT NOT NULL,
  status TEXT NOT NULL,
  cause TEXT,
  audio INTEGER NOT NULL,
  hangup_after_s INTEGER,
  created_at TEXT NOT NULL,
  active_at TEXT,
  ended_at TEXT
);
CREATE TABLE IF NOT EXISTS staging (
  sender TEXT NOT NULL,
  ref_id INTEGER NOT NULL,
  total INTEGER NOT NULL,
  seg_index INTEGER NOT NULL,
  text TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  PRIMARY KEY (sender, ref_id, seg_index)
);
CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox(status);
CREATE INDEX IF NOT EXISTS idx_segments_mr ON outbox_segments(mr);
CREATE INDEX IF NOT EXISTS idx_inbox_id ON inbox(id);
CREATE INDEX IF NOT EXISTS idx_media_inbox ON media(inbox_id);
"#;

#[derive(Clone)]
pub struct Db {
    conn: std::sync::Arc<tokio::sync::Mutex<Connection>>,
    media_dir: PathBuf,
}

/// Result of staging an inbound concat part.
pub enum StageResult {
    Complete(Box<InboxRow>),
    Staged,
}

// ===== row mapping (total: null-checked, no panics) =====

fn map_client(r: &rusqlite::Row<'_>) -> rusqlite::Result<ClientRow> {
    Ok(ClientRow {
        id: r.get(0)?,
        name: r.get(1)?,
        created_at: r.get(2)?,
        revoked_at: r.get(3)?,
    })
}

fn map_segment(r: &rusqlite::Row<'_>) -> rusqlite::Result<SegmentRow> {
    let status: String = r.get(3)?;
    Ok(SegmentRow {
        outbox_id: r.get(0)?,
        seg_index: r.get(1)?,
        mr: r.get(2)?,
        status: match status.as_str() {
            "delivered" => TransportStatus::Delivered,
            "failed" => TransportStatus::Failed,
            _ => TransportStatus::Pending,
        },
        error: r.get(4)?,
        delivered_at: r.get(5)?,
    })
}

fn map_outbox(r: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxRow> {
    let status: String = r.get(5)?;
    Ok(OutboxRow {
        id: r.get(0)?,
        client_id: r.get(1)?,
        to_num: r.get(2)?,
        text: r.get(3)?,
        want_dr: r.get::<_, i64>(4)? != 0,
        status: match status.as_str() {
            "delivered" => TransportStatus::Delivered,
            "failed" => TransportStatus::Failed,
            _ => TransportStatus::Pending,
        },
        attempts: r.get(6)?,
        created_at: r.get(7)?,
        submitted_at: r.get(8)?,
        delivered_at: r.get(9)?,
        error: r.get(10)?,
        vp_deadline: r.get(11)?,
        segments: Vec::new(),
    })
}

const OUTBOX_COLS: &str =
    "id, client_id, to_num, text, want_dr, status, attempts, created_at, submitted_at, delivered_at, error, vp_deadline";

fn map_inbox(r: &rusqlite::Row<'_>) -> rusqlite::Result<InboxRow> {
    let channel: String = r.get(2)?;
    let fetch: Option<String> = r.get(4)?;
    Ok(InboxRow {
        id: r.get(0)?,
        sender: r.get(1)?,
        channel: if channel == "mms" { Channel::Mms } else { Channel::Sms },
        text: r.get(3)?,
        fetch: fetch.map(|f| if f == "ok" { FetchState::Ok } else { FetchState::Unfetchable }),
        media: Vec::new(),
        received_at: r.get(5)?,
        read: r.get::<_, i64>(6)? != 0,
    })
}

const INBOX_COLS: &str = "id, sender, channel, text, fetch, received_at, read";

fn map_media(r: &rusqlite::Row<'_>) -> rusqlite::Result<MediaRow> {
    Ok(MediaRow {
        id: r.get(0)?,
        inbox_id: r.get(1)?,
        name: r.get(2)?,
        content_type: r.get(3)?,
        bytes: r.get(4)?,
        path: r.get(5)?,
        created_at: r.get(6)?,
    })
}

const MEDIA_COLS: &str = "id, inbox_id, name, content_type, bytes, path, created_at";

fn map_call(r: &rusqlite::Row<'_>) -> rusqlite::Result<CallRow> {
    let direction: String = r.get(2)?;
    let status: String = r.get(4)?;
    Ok(CallRow {
        id: r.get(0)?,
        client_id: r.get(1)?,
        direction: if direction == "in" { Direction::In } else { Direction::Out },
        remote: r.get(3)?,
        status: match status.as_str() {
            "incoming" => CallStatus::Incoming,
            "dialing" => CallStatus::Dialing,
            "active" => CallStatus::Active,
            _ => CallStatus::Ended,
        },
        cause: r.get(5)?,
        audio: r.get::<_, i64>(6)? != 0,
        hangup_after_s: r.get(7)?,
        created_at: r.get(8)?,
        active_at: r.get(9)?,
        ended_at: r.get(10)?,
    })
}

const CALL_COLS: &str =
    "id, client_id, direction, remote, status, cause, audio, hangup_after_s, created_at, active_at, ended_at";

impl Db {
    /// Open (creating parent dirs), run migrations, set WAL + foreign_keys.
    pub fn open(path: &Path, media_dir: &Path) -> anyhow::Result<Db> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir_all(media_dir)?;
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
            media_dir: media_dir.to_path_buf(),
        })
    }

    fn media_path_for(&self, id: i64) -> PathBuf {
        // Generated-id filename only (spec §7 path rule).
        self.media_dir.join(format!("m{id}.bin"))
    }

    async fn load_outbox_segments(&self, rows: &mut Vec<OutboxRow>) -> anyhow::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().await;
        for row in rows.iter_mut() {
            let mut stmt = conn.prepare(
                "SELECT outbox_id, seg_index, mr, status, error, delivered_at
                 FROM outbox_segments WHERE outbox_id = ?1 ORDER BY seg_index",
            )?;
            let segs: Vec<SegmentRow> = stmt
                .query_map(params![row.id], map_segment)?
                .collect::<Result<_, _>>()?;
            row.segments = segs;
        }
        Ok(())
    }

    async fn load_inbox_media(&self, rows: &mut Vec<InboxRow>) -> anyhow::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().await;
        for row in rows.iter_mut() {
            let mut stmt = conn.prepare(&format!(
                "SELECT {MEDIA_COLS} FROM media WHERE inbox_id = ?1 ORDER BY id"
            ))?;
            let media: Vec<MediaRow> = stmt
                .query_map(params![row.id], map_media)?
                .collect::<Result<_, _>>()?;
            row.media = media;
        }
        Ok(())
    }

    fn outbox_by_id(conn: &Connection, id: i64) -> anyhow::Result<Option<OutboxRow>> {
        let mut row = conn
            .query_row(
                &format!("SELECT {OUTBOX_COLS} FROM outbox WHERE id = ?1"),
                params![id],
                map_outbox,
            )
            .optional()?;
        if let Some(r) = row.as_mut() {
            let mut stmt = conn.prepare(
                "SELECT outbox_id, seg_index, mr, status, error, delivered_at
                 FROM outbox_segments WHERE outbox_id = ?1 ORDER BY seg_index",
            )?;
            r.segments = stmt.query_map(params![id], map_segment)?.collect::<Result<_, _>>()?;
        }
        Ok(row)
    }

    // ===== clients =====

    /// Exact SHA-256 hex lookup for bearer auth; revoked rows excluded.
    pub async fn client_by_token_hash(&self, hex64: &str) -> Option<ClientRow> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, name, created_at, revoked_at FROM clients
             WHERE token_hash = ?1 AND revoked_at IS NULL",
            params![hex64],
            map_client,
        )
        .optional()
        .unwrap_or(None) // DB unavailable → auth fails closed (spec §7)
    }

    /// Create a client; `token_hash` is the SHA-256 hex of the plaintext
    /// the CLI generated (db never sees or stores plaintext).
    pub async fn add_client(&self, name: &str, token_hash: &str) -> anyhow::Result<ClientRow> {
        let conn = self.conn.lock().await;
        let created = now_ts();
        conn.execute(
            "INSERT INTO clients (name, token_hash, created_at) VALUES (?1, ?2, ?3)",
            params![name.trim(), token_hash, created],
        )?;
        let id = conn.last_insert_rowid();
        Ok(ClientRow { id, name: name.trim().to_string(), created_at: created, revoked_at: None })
    }

    /// Revoke by name or numeric id string; false if nothing matched.
    pub async fn revoke_client(&self, name_or_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().await;
        let revoked = now_ts();
        let n = if let Ok(id) = name_or_id.trim().parse::<i64>() {
            conn.execute(
                "UPDATE clients SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                params![revoked, id],
            )?
        } else {
            conn.execute(
                "UPDATE clients SET revoked_at = ?1 WHERE name = ?2 AND revoked_at IS NULL",
                params![revoked, name_or_id.trim()],
            )?
        };
        Ok(n > 0)
    }

    pub async fn list_clients(&self) -> anyhow::Result<Vec<ClientRow>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, revoked_at FROM clients ORDER BY id",
        )?;
        Ok(stmt.query_map([], map_client)?.collect::<Result<_, _>>()?)
    }

    pub async fn client_name(&self, id: i64) -> Option<String> {
        let conn = self.conn.lock().await;
        conn.query_row("SELECT name FROM clients WHERE id = ?1", params![id], |r| r.get(0))
            .optional()
            .unwrap_or(None)
    }

    // ===== webhook =====

    pub async fn get_webhook(&self, client_id: i64) -> Option<WebhookRow> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT client_id, url, secret, failing, last_error, last_ok FROM webhooks
             WHERE client_id = ?1",
            params![client_id],
            |r| {
                Ok(WebhookRow {
                    client_id: r.get(0)?,
                    url: r.get(1)?,
                    secret: r.get(2)?,
                    failing: r.get::<_, i64>(3)? != 0,
                    last_error: r.get(4)?,
                    last_ok: r.get(5)?,
                })
            },
        )
        .optional()
        .unwrap_or(None)
    }

    pub async fn set_webhook(&self, client_id: i64, url: &str, secret: &str) -> anyhow::Result<WebhookRow> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO webhooks (client_id, url, secret) VALUES (?1, ?2, ?3)
             ON CONFLICT(client_id) DO UPDATE SET url = ?2, secret = ?3, failing = 0, last_error = NULL, last_ok = NULL",
            params![client_id, url, secret],
        )?;
        Ok(WebhookRow {
            client_id,
            url: url.to_string(),
            secret: secret.to_string(),
            failing: false,
            last_error: None,
            last_ok: None,
        })
    }

    pub async fn set_webhook_result(&self, client_id: i64, failing: bool, last_error: Option<&str>) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        let now = now_ts();
        if failing {
            conn.execute(
                "UPDATE webhooks SET failing = 1, last_error = ?2 WHERE client_id = ?1",
                params![client_id, last_error],
            )?;
        } else {
            conn.execute(
                "UPDATE webhooks SET failing = 0, last_error = NULL, last_ok = ?2 WHERE client_id = ?1",
                params![client_id, now],
            )?;
        }
        Ok(())
    }

    /// All non-null webhooks (for the dispatcher at startup).
    pub async fn all_webhooks(&self) -> anyhow::Result<Vec<WebhookRow>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT client_id, url, secret, failing, last_error, last_ok FROM webhooks",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(WebhookRow {
                    client_id: r.get(0)?,
                    url: r.get(1)?,
                    secret: r.get(2)?,
                    failing: r.get::<_, i64>(3)? != 0,
                    last_error: r.get(4)?,
                    last_ok: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ===== outbox (SMS) =====

    /// DELETE /v1/webhook — clear this client's webhook (secret included).
    pub async fn clear_webhook(&self, client_id: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM webhooks WHERE client_id = ?1", params![client_id])?;
        Ok(())
    }

    /// Insert a queued message + pending segments.
    pub async fn queue_sms(
        &self,
        client_id: i64,
        to: &str,
        text: &str,
        want_dr: bool,
        segment_count: i64,
        vp_deadline: String,
    ) -> anyhow::Result<OutboxRow> {
        let mut conn = self.conn.lock().await;
        let created = now_ts();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO outbox (client_id, to_num, text, want_dr, status, created_at, vp_deadline)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6)",
            params![client_id, to, text, want_dr as i64, created, vp_deadline],
        )?;
        let id = tx.last_insert_rowid();
        for idx in 0..segment_count {
            tx.execute(
                "INSERT INTO outbox_segments (outbox_id, seg_index, status) VALUES (?1, ?2, 'pending')",
                params![id, idx],
            )?;
        }
        tx.commit()?;
        drop(conn);
        Ok(OutboxRow {
            id,
            client_id,
            to_num: to.to_string(),
            text: text.to_string(),
            want_dr,
            status: TransportStatus::Pending,
            attempts: 0,
            created_at: created,
            submitted_at: None,
            delivered_at: None,
            error: None,
            vp_deadline,
            segments: (0..segment_count)
                .map(|i| SegmentRow {
                    outbox_id: id,
                    seg_index: i,
                    mr: None,
                    status: TransportStatus::Pending,
                    error: None,
                    delivered_at: None,
                })
                .collect(),
        })
    }

    /// Pending message count (queue_limit → 503 queue_full).
    pub async fn pending_outbox_count(&self) -> anyhow::Result<i64> {
        let conn = self.conn.lock().await;
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM outbox WHERE status = 'pending'",
            [],
            |r| r.get(0),
        )?)
    }

    /// Claim sendable rows for the single modem worker: pending, retry
    /// window open. Bumps attempts (the claim unit — no double submit).
    pub async fn take_sendable_outbox(&self, limit: usize) -> anyhow::Result<Vec<OutboxRow>> {
        let mut conn = self.conn.lock().await;
        let now = now_ts();
        let tx = conn.transaction()?;
        let ids: Vec<i64> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM outbox
                 WHERE status = 'pending'
                   AND (next_attempt_at IS NULL OR next_attempt_at <= ?1)
                   AND EXISTS (SELECT 1 FROM outbox_segments s
                               WHERE s.outbox_id = outbox.id AND s.mr IS NULL)
                 ORDER BY id LIMIT ?2",
            )?;
            let ids = stmt
                .query_map(params![now, limit as i64], |r| r.get(0))?
                .collect::<Result<Vec<i64>, _>>()?;
            ids
        };
        let mut rows = Vec::with_capacity(ids.len());
        for id in ids {
            tx.execute(
                "UPDATE outbox SET attempts = attempts + 1 WHERE id = ?1",
                params![id],
            )?;
            if let Some(r) = Self::outbox_by_id_tx(&tx, id)? {
                rows.push(r);
            }
        }
        tx.commit()?;
        Ok(rows)
    }

    fn outbox_by_id_tx(tx: &rusqlite::Transaction<'_>, id: i64) -> anyhow::Result<Option<OutboxRow>> {
        let mut row = tx
            .query_row(
                &format!("SELECT {OUTBOX_COLS} FROM outbox WHERE id = ?1"),
                params![id],
                map_outbox,
            )
            .optional()?;
        if let Some(r) = row.as_mut() {
            let mut stmt = tx.prepare(
                "SELECT outbox_id, seg_index, mr, status, error, delivered_at
                 FROM outbox_segments WHERE outbox_id = ?1 ORDER BY seg_index",
            )?;
            r.segments = stmt.query_map(params![id], map_segment)?.collect::<Result<_, _>>()?;
        }
        Ok(row)
    }

    /// Record TP-MR for one segment; first MR stamps outbox.submitted_at.
    pub async fn assign_segment_mr(&self, outbox_id: i64, seg_index: i64, mr: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE outbox_segments SET mr = ?3 WHERE outbox_id = ?1 AND seg_index = ?2",
            params![outbox_id, seg_index, mr],
        )?;
        conn.execute(
            "UPDATE outbox SET submitted_at = COALESCE(submitted_at, ?2) WHERE id = ?1",
            params![outbox_id, now_ts()],
        )?;
        Ok(())
    }

    /// Per-segment state from a CDS or hard error.
    pub async fn set_segment_state(
        &self,
        outbox_id: i64,
        seg_index: i64,
        status: TransportStatus,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        match status {
            TransportStatus::Delivered => {
                conn.execute(
                    "UPDATE outbox_segments
                     SET status = 'delivered', error = ?4, delivered_at = ?3
                     WHERE outbox_id = ?1 AND seg_index = ?2",
                    params![outbox_id, seg_index, now_ts(), error],
                )?;
            }
            TransportStatus::Failed => {
                conn.execute(
                    "UPDATE outbox_segments
                     SET status = 'failed', error = ?4
                     WHERE outbox_id = ?1 AND seg_index = ?2",
                    params![outbox_id, seg_index, now_ts(), error],
                )?;
            }
            TransportStatus::Pending => {
                conn.execute(
                    "UPDATE outbox_segments SET status = 'pending', error = ?4
                     WHERE outbox_id = ?1 AND seg_index = ?2",
                    params![outbox_id, seg_index, now_ts(), error],
                )?;
            }
        }
        Ok(())
    }

    /// Find outbox row id by segment TP-MR (CDS join key).
    pub async fn outbox_id_by_mr(&self, mr: i64) -> anyhow::Result<Option<(i64, i64)>> {
        let conn = self.conn.lock().await;
        Ok(conn
            .query_row(
                "SELECT outbox_id, seg_index FROM outbox_segments WHERE mr = ?1",
                params![mr],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// CDS rollup: all delivered → delivered; any failed → failed+error.
    pub async fn rollup_outbox(&self, outbox_id: i64) -> anyhow::Result<Option<OutboxRow>> {
        let conn = self.conn.lock().await;
        let (delivered, failed_err, pending): (i64, Option<String>, i64) = conn.query_row(
            "SELECT
               SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END),
               (SELECT error FROM outbox_segments WHERE outbox_id = ?1 AND status = 'failed' LIMIT 1),
               SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END)
             FROM outbox_segments WHERE outbox_id = ?1",
            params![outbox_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if pending > 0 {
            return Ok(None); // still in flight
        }
        if delivered > 0 && failed_err.is_none() {
            conn.execute(
                "UPDATE outbox SET status = 'delivered', delivered_at = ?2 WHERE id = ?1 AND status = 'pending'",
                params![outbox_id, now_ts()],
            )?;
        } else if let Some(err) = failed_err {
            conn.execute(
                "UPDATE outbox SET status = 'failed', error = ?2 WHERE id = ?1 AND status = 'pending'",
                params![outbox_id, err],
            )?;
        }
        let row = Self::outbox_by_id(&conn, outbox_id)?;
        Ok(row)
    }

    /// Fail rows whose vp_deadline passed with no_delivery_report.
    pub async fn expire_vp_deadlines(&self) -> anyhow::Result<Vec<OutboxRow>> {
        let mut conn = self.conn.lock().await;
        let now = now_ts();
        let tx = conn.transaction()?;
        let ids: Vec<i64> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM outbox WHERE status = 'pending' AND vp_deadline <= ?1",
            )?;
            let ids = stmt
                .query_map(params![now], |r| r.get(0))?
                .collect::<Result<Vec<i64>, _>>()?;
            ids
        };
        let mut rows = Vec::with_capacity(ids.len());
        for id in ids {
            tx.execute(
                "UPDATE outbox SET status = 'failed', error = 'no_delivery_report' WHERE id = ?1",
                params![id],
            )?;
            if let Some(r) = Self::outbox_by_id_tx(&tx, id)? {
                rows.push(r);
            }
        }
        tx.commit()?;
        Ok(rows)
    }

    /// Transient failure: back to pending, retry window opens after
    /// retry_interval_s. Hard retry exhaustion is the worker's call.
    pub async fn mark_outbox_retrying(
        &self,
        outbox_id: i64,
        retry_interval_s: u64,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        let next = ts_plus(retry_interval_s as i64);
        conn.execute(
            "UPDATE outbox SET status = 'pending', error = ?3, next_attempt_at = ?2
             WHERE id = ?1 AND status = 'pending'",
            params![outbox_id, next, error],
        )?;
        conn.execute(
            "UPDATE outbox_segments SET status = 'pending'
             WHERE outbox_id = ?1 AND mr IS NULL",
            params![outbox_id],
        )?;
        Ok(())
    }

    /// Hard failure of the whole message (mapped error string).
    pub async fn fail_outbox(&self, outbox_id: i64, error: &str) -> anyhow::Result<Option<OutboxRow>> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE outbox SET status = 'failed', error = ?2 WHERE id = ?1",
            params![outbox_id, error],
        )?;
        conn.execute(
            "UPDATE outbox_segments SET status = 'failed', error = ?2
             WHERE outbox_id = ?1 AND status = 'pending'",
            params![outbox_id, error],
        )?;
        let row = Self::outbox_by_id(&conn, outbox_id)?;
        Ok(row)
    }

    /// Per-client scoped when client_id is Some (spec §7 ownership).
    pub async fn list_outbox(
        &self,
        client_id: Option<i64>,
        status: Option<TransportStatus>,
    ) -> anyhow::Result<Vec<OutboxRow>> {
        let conn = self.conn.lock().await;
        let st = status.map(|s| s.as_str().to_string());
        let mut rows: Vec<OutboxRow> = match (client_id, st) {
            (Some(c), Some(s)) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {OUTBOX_COLS} FROM outbox WHERE client_id = ?1 AND status = ?2 ORDER BY id DESC"
                ))?;
                stmt.query_map(params![c, s], map_outbox)?.collect::<Result<_, _>>()?
            }
            (Some(c), None) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {OUTBOX_COLS} FROM outbox WHERE client_id = ?1 ORDER BY id DESC"
                ))?;
                stmt.query_map(params![c], map_outbox)?.collect::<Result<_, _>>()?
            }
            (None, Some(s)) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {OUTBOX_COLS} FROM outbox WHERE status = ?1 ORDER BY id DESC"
                ))?;
                stmt.query_map(params![s], map_outbox)?.collect::<Result<_, _>>()?
            }
            (None, None) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {OUTBOX_COLS} FROM outbox ORDER BY id DESC"
                ))?;
                stmt.query_map([], map_outbox)?.collect::<Result<_, _>>()?
            }
        };
        drop(conn);
        self.load_outbox_segments(&mut rows).await?;
        Ok(rows)
    }

    /// Ownership-checked: None = no such id; caller distinguishes 404.
    /// Foreign rows also return None (resource-model 404, spec §3).
    pub async fn get_outbox_scoped(&self, id: i64, client_id: i64) -> anyhow::Result<Option<OutboxRow>> {
        let conn = self.conn.lock().await;
        let owned: Option<i64> = conn
            .query_row(
                "SELECT id FROM outbox WHERE id = ?1 AND client_id = ?2",
                params![id, client_id],
                |r| r.get(0),
            )
            .optional()?;
        if owned.is_none() {
            return Ok(None);
        }
        let row = Self::outbox_by_id(&conn, id)?;
        Ok(row)
    }

    // ===== inbox =====

    pub async fn insert_inbox_sms(&self, sender: &str, text: &str) -> anyhow::Result<InboxRow> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO inbox (sender, channel, text, received_at) VALUES (?1, 'sms', ?2, ?3)",
            params![sender, text, now_ts()],
        )?;
        let id = conn.last_insert_rowid();
        Ok(InboxRow {
            id,
            sender: sender.to_string(),
            channel: Channel::Sms,
            text: text.to_string(),
            fetch: None,
            media: Vec::new(),
            received_at: now_ts(),
            read: false,
        })
    }

    /// Stage a concat part keyed (sender, ref, seg_index). When the group
    /// completes, assemble in index order into one row and clear staging.
    pub async fn stage_inbox_part(
        &self,
        sender: &str,
        reference: u8,
        total: u8,
        seg_index: u8,
        text: &str,
    ) -> anyhow::Result<StageResult> {
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO staging (sender, ref_id, total, seg_index, text, first_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![sender, reference as i64, total as i64, seg_index as i64, text, now_ts()],
        )?;
        let have: i64 = tx.query_row(
            "SELECT COUNT(*) FROM staging WHERE sender = ?1 AND ref_id = ?2",
            params![sender, reference as i64],
            |r| r.get(0),
        )?;
        let expected_total: i64 = tx.query_row(
            "SELECT total FROM staging WHERE sender = ?1 AND ref_id = ?2 LIMIT 1",
            params![sender, reference as i64],
            |r| r.get(0),
        )
        .unwrap_or(total as i64);
        if have < expected_total.max(1) {
            tx.commit()?;
            return Ok(StageResult::Staged);
        }
        let parts: Vec<(i64, String)> = {
            let mut stmt = tx.prepare(
                "SELECT seg_index, text FROM staging
                 WHERE sender = ?1 AND ref_id = ?2 ORDER BY seg_index",
            )?;
            stmt.query_map(params![sender, reference as i64], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<Result<_, _>>()?
        };
        let assembled: String = parts.into_iter().map(|(_, t)| t).collect();
        tx.execute(
            "INSERT INTO inbox (sender, channel, text, received_at) VALUES (?1, 'sms', ?2, ?3)",
            params![sender, assembled, now_ts()],
        )?;
        let inbox_id = tx.last_insert_rowid();
        tx.execute(
            "DELETE FROM staging WHERE sender = ?1 AND ref_id = ?2",
            params![sender, reference as i64],
        )?;
        tx.commit()?;
        Ok(StageResult::Complete(Box::new(InboxRow {
            id: inbox_id,
            sender: sender.to_string(),
            channel: Channel::Sms,
            text: assembled,
            fetch: None,
            media: Vec::new(),
            received_at: now_ts(),
            read: false,
        })))
    }

    /// Flush staging groups older than the window as individual rows —
    /// the gap stays visible, never swallowed (spec §5).
    pub async fn flush_stale_staging(&self, older_than_s: u64) -> anyhow::Result<Vec<InboxRow>> {
        let mut conn = self.conn.lock().await;
        let cutoff = ts_minus(older_than_s as i64);
        let tx = conn.transaction()?;
        let groups: Vec<(String, i64)> = {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT sender, ref_id FROM staging WHERE first_seen < ?1",
            )?;
            let g = stmt
                .query_map(params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            g
        };
        let mut rows = Vec::new();
        for (sender, ref_id) in groups {
            let mut stmt = tx.prepare(
                "SELECT seg_index, text FROM staging
                 WHERE sender = ?1 AND ref_id = ?2 ORDER BY seg_index",
            )?;
            let parts: Vec<(i64, String)> = stmt
                .query_map(params![sender, ref_id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            let text: String = parts.into_iter().map(|(_, t)| t).collect();
            tx.execute(
                "INSERT INTO inbox (sender, channel, text, received_at) VALUES (?1, 'sms', ?2, ?3)",
                params![sender, text, now_ts()],
            )?;
            let inbox_id = tx.last_insert_rowid();
            tx.execute(
                "DELETE FROM staging WHERE sender = ?1 AND ref_id = ?2",
                params![sender, ref_id],
            )?;
            rows.push(InboxRow {
                id: inbox_id,
                sender: sender.clone(),
                channel: Channel::Sms,
                text,
                fetch: None,
                media: Vec::new(),
                received_at: now_ts(),
                read: false,
            });
        }
        tx.commit()?;
        Ok(rows)
    }

    pub async fn list_inbox(
        &self,
        since: Option<i64>,
        unread_only: bool,
        limit: i64,
    ) -> anyhow::Result<Vec<InboxRow>> {
        let conn = self.conn.lock().await;
        let mut rows: Vec<InboxRow> = match (since, unread_only) {
            (Some(s), true) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {INBOX_COLS} FROM inbox WHERE id > ?1 AND read = 0 ORDER BY id ASC LIMIT ?2"
                ))?;
                stmt.query_map(params![s, limit], map_inbox)?.collect::<Result<_, _>>()?
            }
            (Some(s), false) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {INBOX_COLS} FROM inbox WHERE id > ?1 ORDER BY id ASC LIMIT ?2"
                ))?;
                stmt.query_map(params![s, limit], map_inbox)?.collect::<Result<_, _>>()?
            }
            (None, true) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {INBOX_COLS} FROM inbox WHERE read = 0 ORDER BY id ASC LIMIT ?1"
                ))?;
                stmt.query_map(params![limit], map_inbox)?.collect::<Result<_, _>>()?
            }
            (None, false) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {INBOX_COLS} FROM inbox ORDER BY id ASC LIMIT ?1"
                ))?;
                stmt.query_map(params![limit], map_inbox)?.collect::<Result<_, _>>()?
            }
        };
        drop(conn);
        self.load_inbox_media(&mut rows).await?;
        Ok(rows)
    }

    pub async fn get_inbox(&self, id: i64) -> anyhow::Result<Option<InboxRow>> {
        let conn = self.conn.lock().await;
        let mut row: Option<InboxRow> = conn
            .query_row(
                &format!("SELECT {INBOX_COLS} FROM inbox WHERE id = ?1"),
                params![id],
                map_inbox,
            )
            .optional()?;
        drop(conn);
        if let Some(r) = row.as_mut() {
            let mut vec = vec![r.clone()];
            self.load_inbox_media(&mut vec).await?;
            if let Some(loaded) = vec.into_iter().next() {
                *r = loaded;
            }
        }
        Ok(row)
    }

    pub async fn mark_inbox_read(&self, id: i64) -> anyhow::Result<Option<InboxRow>> {
        let conn = self.conn.lock().await;
        let n = conn.execute("UPDATE inbox SET read = 1 WHERE id = ?1", params![id])?;
        if n == 0 {
            return Ok(None);
        }
        drop(conn);
        Ok(self.get_inbox(id).await?)
    }

    /// Delete an inbox row; cascade removes media rows, then files.
    pub async fn delete_inbox(&self, id: i64) -> anyhow::Result<bool> {
        let paths: Vec<String> = {
            let conn = self.conn.lock().await;
            let mut stmt =
                conn.prepare("SELECT path FROM media WHERE inbox_id = ?1")?;
            let p = stmt
                .query_map(params![id], |r| r.get(0))?
                .collect::<Result<Vec<String>, _>>()?;
            p
        };
        let deleted = {
            let conn = self.conn.lock().await;
            conn.execute("DELETE FROM inbox WHERE id = ?1", params![id])? > 0
        };
        if deleted {
            for p in paths {
                let full = self.media_dir.join(&p);
                if let Err(e) = std::fs::remove_file(&full) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(target: "cellmatik::db", path = %p, error = %e, "media file cleanup failed");
                    }
                }
            }
        }
        Ok(deleted)
    }

    /// SSE replay window: id > after, ascending.
    pub async fn inbox_after(&self, after: i64, limit: i64) -> anyhow::Result<Vec<InboxRow>> {
        self.list_inbox(Some(after), false, limit).await
    }

    /// Derived status (spec §3): delivery_capable + last_cds. Self-directed
    /// sends (to our own number) never count toward the blocked verdict.
    pub async fn sms_derived(&self, own_number: Option<&str>) -> anyhow::Result<(String, Option<String>)> {
        let conn = self.conn.lock().await;
        let last_cds: Option<String> = conn
            .query_row(
                "SELECT MAX(delivered_at) FROM outbox WHERE delivered_at IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .optional()?
            .flatten();

        let accepted_no_cds: i64 = {
            let pending_recent: i64 = conn.query_row(
                "SELECT COUNT(*) FROM outbox
                 WHERE submitted_at IS NOT NULL
                   AND delivered_at IS NULL
                   AND status = 'pending'
                   AND created_at >= ?1",
                params![ts_minus(900)],
                |r| r.get(0),
            )?;
            match own_number {
                Some(own) => {
                    let own_clean = own.trim_start_matches('+');
                    let self_sent: i64 = conn.query_row(
                        "SELECT COUNT(*) FROM outbox
                         WHERE submitted_at IS NOT NULL
                           AND delivered_at IS NULL
                           AND status = 'pending'
                           AND created_at >= ?1
                           AND REPLACE(to_num, '+', '') = ?2",
                        params![ts_minus(900), own_clean],
                        |r| r.get(0),
                    )?;
                    (pending_recent - self_sent).max(0)
                }
                None => pending_recent,
            }
        };
        let recent_inbound: i64 = conn.query_row(
            "SELECT COUNT(*) FROM inbox WHERE received_at >= ?1",
            params![ts_minus(900)],
            |r| r.get(0),
        )?;
        let verdict = if accepted_no_cds >= 3 && recent_inbound == 0 {
            "blocked".to_string()
        } else if last_cds.is_some() || recent_inbound > 0 {
            "ok".to_string()
        } else {
            "unknown".to_string()
        };
        Ok((verdict, last_cds))
    }

    // ===== calls =====

    pub async fn insert_call(
        &self,
        client_id: i64,
        direction: Direction,
        remote: &str,
        audio: bool,
        hangup_after_s: Option<i64>,
    ) -> anyhow::Result<CallRow> {
        let conn = self.conn.lock().await;
        let created = now_ts();
        let status = match direction {
            Direction::In => "incoming",
            Direction::Out => "dialing",
        };
        conn.execute(
            "INSERT INTO calls (client_id, direction, remote, status, audio, hangup_after_s, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                client_id,
                direction.as_str(),
                remote,
                status,
                audio as i64,
                hangup_after_s,
                created
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(CallRow {
            id,
            client_id,
            direction,
            remote: remote.to_string(),
            status: match direction {
                Direction::In => CallStatus::Incoming,
                Direction::Out => CallStatus::Dialing,
            },
            cause: None,
            audio,
            hangup_after_s,
            created_at: created,
            active_at: None,
            ended_at: None,
        })
    }

    /// Atomic conditional transition — the claim primitive (spec §7).
    /// Rowcount 0 ⇒ guard failed ⇒ None ⇒ caller maps to 409/404.
    pub async fn transition_call(
        &self,
        id: i64,
        expected: CallStatus,
        next: CallStatus,
        cause: Option<&str>,
    ) -> anyhow::Result<Option<CallRow>> {
        let conn = self.conn.lock().await;
        let now = now_ts();
        let active_stamp = if next == CallStatus::Active { Some(now.clone()) } else { None };
        let ended_stamp = if next == CallStatus::Ended { Some(now.clone()) } else { None };
        let n = conn.execute(
            "UPDATE calls
             SET status = ?3, cause = ?4, active_at = COALESCE(?5, active_at), ended_at = COALESCE(?6, ended_at)
             WHERE id = ?1 AND status = ?2",
            params![
                id,
                expected.as_str(),
                next.as_str(),
                cause,
                active_stamp,
                ended_stamp
            ],
        )?;
        if n == 0 {
            return Ok(None);
        }
        let row: Option<CallRow> = conn
            .query_row(&format!("SELECT {CALL_COLS} FROM calls WHERE id = ?1"), params![id], map_call)
            .optional()?;
        Ok(row)
    }

    /// Lowest-id active client — the bootstrap owner; inbound calls are
    /// attributed to it (calls are a shared dashboard view, spec §3).
    pub async fn first_client_id(&self) -> Option<i64> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id FROM clients WHERE revoked_at IS NULL ORDER BY id LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    pub async fn get_call(&self, id: i64) -> anyhow::Result<Option<CallRow>> {
        let conn = self.conn.lock().await;
        Ok(conn
            .query_row(&format!("SELECT {CALL_COLS} FROM calls WHERE id = ?1"), params![id], map_call)
            .optional()?)
    }

    pub async fn list_calls(
        &self,
        status: Option<CallStatus>,
        since: Option<String>,
    ) -> anyhow::Result<Vec<CallRow>> {
        let conn = self.conn.lock().await;
        let rows: Vec<CallRow> = match (status, since) {
            (Some(s), Some(t)) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {CALL_COLS} FROM calls WHERE status = ?1 AND created_at >= ?2 ORDER BY id DESC"
                ))?;
                stmt.query_map(params![s.as_str(), t], map_call)?.collect::<Result<_, _>>()?
            }
            (Some(s), None) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {CALL_COLS} FROM calls WHERE status = ?1 ORDER BY id DESC"
                ))?;
                stmt.query_map(params![s.as_str()], map_call)?.collect::<Result<_, _>>()?
            }
            (None, Some(t)) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {CALL_COLS} FROM calls WHERE created_at >= ?1 ORDER BY id DESC"
                ))?;
                stmt.query_map(params![t], map_call)?.collect::<Result<_, _>>()?
            }
            (None, None) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {CALL_COLS} FROM calls ORDER BY id DESC"
                ))?;
                stmt.query_map([], map_call)?.collect::<Result<_, _>>()?
            }
        };
        Ok(rows)
    }

    // ===== media =====

    /// Store bytes under a generated id-based filename (spec §7 path rule);
    /// carrier-supplied `name` is column data only.
    pub async fn store_media(
        &self,
        inbox_id: Option<i64>,
        mms_outbox_id: Option<i64>,
        name: &str,
        content_type: &str,
        data: Vec<u8>,
    ) -> anyhow::Result<MediaRow> {
        let bytes = data.len() as i64;
        let id = {
            let conn = self.conn.lock().await;
            conn.execute(
                "INSERT INTO media (inbox_id, mms_outbox_id, name, content_type, bytes, path, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, '', ?6)",
                params![inbox_id, mms_outbox_id, name, content_type, bytes, now_ts()],
            )?;
            let id = conn.last_insert_rowid();
            // Path is derived from the row id — never from input.
            let path = format!("m{id}.bin");
            conn.execute(
                "UPDATE media SET path = ?2 WHERE id = ?1",
                params![id, path],
            )?;
            id
        };
        let file = self.media_path_for(id);
        let res = tokio::task::spawn_blocking(move || std::fs::write(file, data)).await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                // Row without a file is worse than no row: remove it.
                let conn = self.conn.lock().await;
                let _ = conn.execute("DELETE FROM media WHERE id = ?1", params![id]);
                anyhow::bail!("media write failed: {e}");
            }
            Err(e) => anyhow::bail!("media write task failed: {e}"),
        }
        Ok(MediaRow {
            id,
            inbox_id,
            name: name.to_string(),
            content_type: content_type.to_string(),
            bytes,
            path: format!("m{id}.bin"),
            created_at: now_ts(),
        })
    }

    pub async fn get_media(&self, id: i64) -> anyhow::Result<Option<(MediaRow, Vec<u8>)>> {
        let row: Option<MediaRow> = {
            let conn = self.conn.lock().await;
            conn.query_row(
                &format!("SELECT {MEDIA_COLS} FROM media WHERE id = ?1"),
                params![id],
                map_media,
            )
            .optional()?
        };
        let Some(row) = row else { return Ok(None) };
        let file = self.media_dir.join(&row.path);
        let data = tokio::task::spawn_blocking(move || std::fs::read(file))
            .await
            .map_err(|e| anyhow::anyhow!("media read task: {e}"))??;
        Ok(Some((row, data)))
    }

    /// Unlink media files for rows about to be deleted (paths collected
    /// pre-delete, removal post-commit, best effort with logging).
    fn media_paths_for_inbox(tx: &rusqlite::Transaction<'_>, inbox_id: i64) -> anyhow::Result<Vec<String>> {
        let mut stmt = tx.prepare("SELECT path FROM media WHERE inbox_id = ?1")?;
        Ok(stmt
            .query_map(params![inbox_id], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?)
    }

    // ===== MMS =====

    /// Insert an MMS inbox row + store parts as media.
    pub async fn insert_inbox_mms(
        &self,
        sender: &str,
        text: &str,
        fetch: FetchState,
        parts: Vec<(String, String, Vec<u8>)>,
    ) -> anyhow::Result<InboxRow> {
        let received = now_ts();
        let inbox_id = {
            let conn = self.conn.lock().await;
            conn.execute(
                "INSERT INTO inbox (sender, channel, text, fetch, received_at)
                 VALUES (?1, 'mms', ?2, ?3, ?4)",
                params![sender, text, fetch.as_str(), received],
            )?;
            conn.last_insert_rowid()
        };
        let mut media = Vec::with_capacity(parts.len());
        for (name, ctype, data) in parts {
            let m = self
                .store_media(Some(inbox_id), None, &name, &ctype, data)
                .await?;
            media.push(m);
        }
        Ok(InboxRow {
            id: inbox_id,
            sender: sender.to_string(),
            channel: Channel::Mms,
            text: text.to_string(),
            fetch: Some(fetch),
            media,
            received_at: received,
            read: false,
        })
    }

    pub async fn queue_mms(
        &self,
        client_id: i64,
        to: &str,
        text: Option<&str>,
        media: MediaRow,
    ) -> anyhow::Result<MmsOutboxRow> {
        let created = now_ts();
        let id = {
            let conn = self.conn.lock().await;
            conn.execute(
                "INSERT INTO mms_outbox (client_id, to_num, text, media_id, status, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'queued', ?5)",
                params![client_id, to, text, media.id, created],
            )?;
            let id = conn.last_insert_rowid();
            conn.execute(
                "UPDATE media SET mms_outbox_id = ?1 WHERE id = ?2",
                params![id, media.id],
            )?;
            id
        };
        Ok(MmsOutboxRow {
            id,
            client_id,
            to_num: to.to_string(),
            text: text.map(|s| s.to_string()),
            media,
            status: MmsStatus::Queued,
            error: None,
            created_at: created,
            sent_at: None,
        })
    }

    /// Claim queued/retrying rows for the worker: → sending, atomic.
    pub async fn take_sendable_mms(&self, limit: usize) -> anyhow::Result<Vec<MmsOutboxRow>> {
        let conn = self.conn.lock().await;
        let ids: Vec<i64> = {
            let mut stmt = conn.prepare(
                "SELECT id FROM mms_outbox WHERE status IN ('queued','retrying') ORDER BY id LIMIT ?1",
            )?;
            let ids = stmt
                .query_map(params![limit as i64], |r| r.get(0))?
                .collect::<Result<Vec<i64>, _>>()?;
            ids
        };
        let mut rows = Vec::with_capacity(ids.len());
        for id in ids {
            conn.execute(
                "UPDATE mms_outbox SET status = 'sending' WHERE id = ?1",
                params![id],
            )?;
            if let Some(r) = self.mms_row_by_id(&conn, id)? {
                rows.push(r);
            }
        }
        Ok(rows)
    }

    fn mms_row_by_id(&self, conn: &Connection, id: i64) -> anyhow::Result<Option<MmsOutboxRow>> {
        let full: Option<(
            i64, i64, String, Option<String>, String, Option<String>, String, Option<String>, i64,
        )> = conn
            .query_row(
                "SELECT id, client_id, to_num, text, status, error, created_at, sent_at, media_id
                 FROM mms_outbox WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?,
                        r.get(6)?, r.get(7)?, r.get(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((mid, client_id, to_num, text, status, error, created_at, sent_at, media_id)) = full
        else {
            return Ok(None);
        };
        let media: MediaRow = conn
            .query_row(
                &format!("SELECT {MEDIA_COLS} FROM media WHERE id = ?1"),
                params![media_id],
                map_media,
            )
            .optional()?
            .unwrap_or(MediaRow {
                id: media_id,
                inbox_id: None,
                name: String::new(),
                content_type: String::new(),
                bytes: 0,
                path: String::new(),
                created_at: String::new(),
            });
        let st = match status.as_str() {
            "sending" => MmsStatus::Sending,
            "retrying" => MmsStatus::Retrying,
            "sent" => MmsStatus::Sent,
            "delivered" => MmsStatus::Delivered,
            "failed" => MmsStatus::Failed,
            _ => MmsStatus::Queued,
        };
        Ok(Some(MmsOutboxRow {
            id: mid,
            client_id,
            to_num,
            text,
            media,
            status: st,
            error,
            created_at,
            sent_at,
        }))
    }

    pub async fn set_mms_state(
        &self,
        id: i64,
        status: MmsStatus,
        error: Option<&str>,
    ) -> anyhow::Result<Option<MmsOutboxRow>> {
        let conn = self.conn.lock().await;
        let sent = if status == MmsStatus::Sent || status == MmsStatus::Delivered {
            now_ts()
        } else {
            String::new()
        };
        conn.execute(
            "UPDATE mms_outbox SET status = ?2, error = ?3,
             sent_at = CASE WHEN ?2 IN ('sent','delivered') THEN ?4 ELSE sent_at END
             WHERE id = ?1",
            params![id, status.as_str(), error, sent],
        )?;
        let row = self.mms_row_by_id(&conn, id)?;
        Ok(row)
    }

    pub async fn list_mms(
        &self,
        client_id: Option<i64>,
        status: Option<MmsStatus>,
    ) -> anyhow::Result<Vec<MmsOutboxRow>> {
        let conn = self.conn.lock().await;
        let ids: Vec<i64> = match (client_id, status) {
            (Some(c), Some(s)) => {
                let mut stmt = conn.prepare(
                    "SELECT id FROM mms_outbox WHERE client_id = ?1 AND status = ?2 ORDER BY id DESC",
                )?;
                stmt.query_map(params![c, s.as_str()], |r| r.get(0))?.collect::<Result<_, _>>()?
            }
            (Some(c), None) => {
                let mut stmt = conn
                    .prepare("SELECT id FROM mms_outbox WHERE client_id = ?1 ORDER BY id DESC")?;
                stmt.query_map(params![c], |r| r.get(0))?.collect::<Result<_, _>>()?
            }
            (None, Some(s)) => {
                let mut stmt = conn
                    .prepare("SELECT id FROM mms_outbox WHERE status = ?1 ORDER BY id DESC")?;
                stmt.query_map(params![s.as_str()], |r| r.get(0))?.collect::<Result<_, _>>()?
            }
            (None, None) => {
                let mut stmt = conn.prepare("SELECT id FROM mms_outbox ORDER BY id DESC")?;
                stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
            }
        };
        let mut rows = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(r) = self.mms_row_by_id(&conn, id)? {
                rows.push(r);
            }
        }
        Ok(rows)
    }

    pub async fn get_mms_scoped(&self, id: i64, client_id: i64) -> anyhow::Result<Option<MmsOutboxRow>> {
        let conn = self.conn.lock().await;
        let owned: Option<i64> = conn
            .query_row(
                "SELECT id FROM mms_outbox WHERE id = ?1 AND client_id = ?2",
                params![id, client_id],
                |r| r.get(0),
            )
            .optional()?;
        if owned.is_none() {
            return Ok(None);
        }
        self.mms_row_by_id(&conn, id)
    }

    // ===== retention =====

    /// Nightly sweep (spec §4): unread inbox exempt; outbox terminal only;
    /// calls ended only; media cascades to files.
    pub async fn sweep(&self, inbox_days: u64, outbox_days: u64, calls_days: u64) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;

        // Inbox (read only) + their media files.
        let inbox_ids: Vec<i64> = {
            let mut stmt =
                tx.prepare("SELECT id FROM inbox WHERE read = 1 AND received_at < ?1")?;
            let ids = stmt
                .query_map(params![ts_days_ago(inbox_days as i64)], |r| r.get(0))?
                .collect::<Result<Vec<i64>, _>>()?;
            ids
        };
        let mut files: Vec<String> = Vec::new();
        for id in &inbox_ids {
            files.extend(Self::media_paths_for_inbox(&tx, *id)?);
        }
        if !inbox_ids.is_empty() {
            let placeholders = inbox_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            // ids are internal row ids, not user input — but bind anyway.
            let params_vec: Vec<&dyn rusqlite::ToSql> =
                inbox_ids.iter().map(|i| i as &dyn rusqlite::ToSql).collect();
            tx.execute(&format!("DELETE FROM inbox WHERE id IN ({placeholders})"), params_vec.as_slice())?;
        }

        // Outbox terminal rows + segments cascade via FK.
        tx.execute(
            "DELETE FROM outbox WHERE status IN ('delivered','failed') AND created_at < ?1",
            params![ts_days_ago(outbox_days as i64)],
        )?;

        // MMS outbox terminal rows; their media rows + files too.
        let mms_media: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT m.path FROM media m JOIN mms_outbox o ON o.media_id = m.id
                 WHERE o.status IN ('sent','delivered','failed') AND o.created_at < ?1",
            )?;
            let p = stmt
                .query_map(params![ts_days_ago(outbox_days as i64)], |r| r.get(0))?
                .collect::<Result<Vec<String>, _>>()?;
            p
        };
        files.extend(mms_media);
        tx.execute(
            "DELETE FROM media WHERE mms_outbox_id IN (
               SELECT id FROM mms_outbox WHERE status IN ('sent','delivered','failed') AND created_at < ?1
             )",
            params![ts_days_ago(outbox_days as i64)],
        )?;
        tx.execute(
            "DELETE FROM mms_outbox WHERE status IN ('sent','delivered','failed') AND created_at < ?1",
            params![ts_days_ago(outbox_days as i64)],
        )?;

        // Calls ended only.
        tx.execute(
            "DELETE FROM calls WHERE status = 'ended' AND ended_at < ?1",
            params![ts_days_ago(calls_days as i64)],
        )?;

        // Staging junk older than a day (safety; 300 s flush normally handles).
        tx.execute("DELETE FROM staging WHERE first_seen < ?1", params![ts_days_ago(1)])?;

        tx.commit()?;
        drop(conn);
        for p in files {
            let full = self.media_dir.join(&p);
            if let Err(e) = std::fs::remove_file(&full) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(target: "cellmatik::db", path = %p, error = %e, "sweep file cleanup failed");
                }
            }
        }
        Ok(())
    }
}
