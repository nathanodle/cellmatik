//! Typed event envelope (spec §3): the SSE broadcast bus, the webhook
//! dispatcher (HMAC-SHA256 signed, 5 attempts, 10 s → 160 s backoff,
//! persistent failure → `failing: true`), and the single JSON shapers
//! that make GET responses, SSE `data:`, and webhook bodies byte-identical.
//!
//! SECURITY (spec §7): webhook secrets never logged; item JSON never
//! includes media filesystem paths; nothing here panics on external input.

use crate::config::Config;
use crate::db::Db;
use crate::types::*;
use futures::stream::Stream;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

pub const WEBHOOK_ATTEMPTS: u32 = 5;
pub const WEBHOOK_BACKOFF_BASE_S: u64 = 10; // 10, 20, 40, 80, 160

#[derive(Clone)]
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<Event>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(512);
        EventBus { tx }
    }

    /// Publish to all subscribers (SSE fan-out + webhook dispatcher).
    pub fn publish(&self, ev: Event) {
        // No subscribers is normal at boot; send handles it.
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

// ===== item shapers — the ONE place item JSON is built =====

fn ts(v: &str) -> &str {
    v
}

/// SMS outbox item (spec §3): full GET shape; the 202 response carries the
/// same object (superset of the documented minimum — every documented
/// field present with the same value).
pub fn sms_item_json(row: &OutboxRow, cfg: &Config) -> serde_json::Value {
    let mut v = serde_json::json!({
        "id": row.id,
        "to": row.to_num,
        "text": row.text,
        "status": row.status.as_str(),
        "segments": row.segments.len(),
        "attempts": row.attempts,
        "created_at": ts(&row.created_at),
        "submitted_at": row.submitted_at,
        "delivered_at": row.delivered_at,
        "error": row.error,
    });
    if let Some(obj) = v.as_object_mut() {
        if let Some(detail) = outbox_detail(row, cfg.stale_after_s) {
            obj.insert("detail".into(), serde_json::json!(serde_json::to_value(detail).unwrap_or_default()));
            obj.insert("check_after_s".into(), serde_json::json!(check_after_s(row, cfg.stale_after_s)));
        }
        if row.status == TransportStatus::Failed {
            let retryable = row.error.as_deref().map(retryable).unwrap_or(false);
            obj.insert("retryable".into(), serde_json::json!(retryable));
        }
    }
    v
}

/// Inbox item (GET /v1/messages, message/mms event data, webhook bodies) —
/// byte-identical across all three surfaces by construction.
pub fn inbox_item_json(row: &InboxRow) -> serde_json::Value {
    let media: Vec<serde_json::Value> = row
        .media
        .iter()
        .map(|m| {
            serde_json::json!({
                "id": m.id,
                "name": m.name,
                "type": m.content_type,
                "bytes": m.bytes,
            })
        })
        .collect();
    let mut v = serde_json::json!({
        "id": row.id,
        "from": row.sender,
        "channel": row.channel.as_str(),
        "text": row.text,
        "media": media,
        "received_at": ts(&row.received_at),
        "read": row.read,
    });
    if let Some(f) = row.fetch {
        if let Some(obj) = v.as_object_mut() {
            obj.insert("fetch".into(), serde_json::json!(f.as_str()));
        }
    }
    v
}

/// Call item — outbound rows key the remote as `to`, inbound as `from`
/// (spec §3 examples).
pub fn call_item_json(row: &CallRow, owner: Option<&str>) -> serde_json::Value {
    let remote_key = if row.direction == Direction::Out { "to" } else { "from" };
    let v = serde_json::json!({
        "id": row.id,
        "direction": row.direction.as_str(),
        (remote_key): row.remote,
        "status": row.status.as_str(),
        "cause": row.cause,
        "owner": owner,
        "audio": row.audio,
        "hangup_after_s": row.hangup_after_s,
        "created_at": ts(&row.created_at),
        "active_at": row.active_at,
        "ended_at": row.ended_at,
    });
    v
}

/// MMS outbox item (spec §3 MMS): pending rows carry detail + poll hint.
pub fn mms_item_json(row: &MmsOutboxRow) -> serde_json::Value {
    let mut v = serde_json::json!({
        "id": row.id,
        "to": row.to_num,
        "text": row.text,
        "media": [{
            "name": row.media.name,
            "type": row.media.content_type,
            "bytes": row.media.bytes,
        }],
        "status": row.status,
        "error": row.error,
        "created_at": ts(&row.created_at),
        "sent_at": row.sent_at,
    });
    if let Some(obj) = v.as_object_mut() {
        if let Some(detail) = mms_detail(row) {
            obj.insert("detail".into(), serde_json::json!(serde_json::to_value(detail).unwrap_or_default()));
            obj.insert("check_after_s".into(), serde_json::json!(2));
        }
        if row.status == MmsStatus::Failed {
            let retryable = row
                .error
                .as_deref()
                .map(|e| matches!(e, "mms_unavailable" | "send_timeout"))
                .unwrap_or(false);
            obj.insert("retryable".into(), serde_json::json!(retryable));
        }
    }
    v
}

/// Composed GET /v1/status body (spec §3): modem snapshot + derived sms
/// fields + voice/mms capability. `own_number` (SIM MSISDN) excludes
/// self-directed sends from the blocked verdict.
pub async fn status_json(
    snapshot: &ModemSnapshot,
    db: &Db,
    cfg: &Arc<Config>,
    mms_bearer: &str,
) -> serde_json::Value {
    let own = if snapshot.sim.msisdn.is_empty() { None } else { Some(snapshot.sim.msisdn.as_str()) };
    let (delivery_capable, last_cds) = db.sms_derived(own).await.unwrap_or_else(|e| {
        tracing::warn!(target: "cellmatik::envelope", error = %e, "sms_derived failed");
        ("unknown".to_string(), None)
    });
    serde_json::json!({
        "modem": snapshot.modem,
        "sim": snapshot.sim,
        "network": snapshot.network,
        "sms": {
            "delivery_capable": delivery_capable,
            "last_cds": last_cds,
        },
        "voice": { "supported": cfg.profile.voice_supported() },
        "mms": { "enabled": cfg.mms.enabled, "bearer": mms_bearer },
    })
}

// ===== webhook dispatcher =====

/// One blocking delivery attempt (ureq). Returns Err(message) on any
/// non-2xx/transport failure.
fn deliver_once(
    url: &str,
    secret: &str,
    body: &[u8],
    timeout_s: u64,
) -> Result<(), String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("hmac init: {e}"))?;
    mac.update(body);
    let sig = hex::encode(mac.finalize().into_bytes());
    let resp = ureq::post(url)
        .timeout(Duration::from_secs(timeout_s))
        .set("Content-Type", "application/json")
        .set("X-Webhook-Signature", &format!("sha256={sig}"))
        .send_bytes(body)
        .map_err(|e| format!("{e}"))?;
    let status = resp.status();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("http_{status}"))
    }
}

/// Spawn the LAN-side delivery loop. Webhooks keep working when the modem
/// is dead (spec §5 recovery rung ④) — this task only needs the DB and bus.
pub fn spawn_webhook_dispatcher(db: Db, bus: EventBus, cfg: Arc<Config>) {
    tokio::spawn(async move {
        let mut rx = bus.subscribe();
        loop {
            let ev = match rx.recv().await {
                Ok(e) => e,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(target: "cellmatik::webhook", skipped = n, "webhook bus lagged");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            let body = serde_json::json!({"type": ev.kind, "data": ev.data});
            let body_bytes = match serde_json::to_vec(&body) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let hooks = db.all_webhooks().await.unwrap_or_default();
            for hook in hooks {
                let db = db.clone();
                let url = hook.url.clone();
                let secret = hook.secret.clone();
                let payload = body_bytes.clone();
                let timeout_s = cfg.webhook_timeout_s;
                let client_id = hook.client_id;
                tokio::spawn(async move {
                    let mut attempt: u32 = 0;
                    loop {
                        attempt += 1;
                        let res = tokio::task::spawn_blocking({
                            let url = url.clone();
                            let secret = secret.clone();
                            let payload = payload.clone();
                            move || deliver_once(&url, &secret, &payload, timeout_s)
                        })
                        .await;
                        match res {
                            Ok(Ok(())) => {
                                if let Err(e) = db.set_webhook_result(client_id, false, None).await {
                                    tracing::warn!(target: "cellmatik::webhook", error = %e, "webhook state write failed");
                                }
                                break;
                            }
                            Ok(Err(msg)) => {
                                if attempt >= WEBHOOK_ATTEMPTS {
                                    tracing::warn!(target: "cellmatik::webhook", url = %url, last_error = %msg, "webhook marked failing");
                                    let _ = db.set_webhook_result(client_id, true, Some(&msg)).await;
                                    break;
                                }
                                let backoff = WEBHOOK_BACKOFF_BASE_S
                                    .saturating_mul(1u64 << (attempt - 1).min(4))
                                    .min(160);
                                tokio::time::sleep(Duration::from_secs(backoff)).await;
                            }
                            Err(_) => break, // join failure — drop this delivery
                        }
                    }
                });
            }
        }
    });
}

// ===== SSE =====

fn sse_payload(ev: &Event) -> axum::response::sse::Event {
    let body = serde_json::json!({"type": ev.kind, "data": ev.data});
    let data = serde_json::to_string(&body).unwrap_or_else(|_| "{}".into());
    let mut out = axum::response::sse::Event::default().data(data);
    if let Some(id) = ev.inbox_id {
        out = out.id(id.to_string());
    }
    out
}

struct SseState {
    db: Db,
    rx: tokio::sync::broadcast::Receiver<Event>,
    queue: VecDeque<axum::response::sse::Event>,
    last_id: Option<i64>,
    replayed: bool,
}

/// SSE event stream: optional replay of inbox rows with id > last_event_id
/// (message/mms events only — call/dtmf/modem events are live-only per
/// spec §3), then live events. Heartbeat keep-alive is attached by the
/// api layer (Sse::keep_alive) using cfg.heartbeat_s.
pub fn sse_stream(
    db: Db,
    bus: EventBus,
    _cfg: Arc<Config>,
    last_event_id: Option<i64>,
) -> impl Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>> + Send + 'static {
    let rx = bus.subscribe();
    futures::stream::unfold(
        SseState { db, rx, queue: VecDeque::new(), last_id: last_event_id, replayed: false },
        |mut s: SseState| async move {
            if let Some(ev) = s.queue.pop_front() {
                return Some((Ok(ev), s));
            }
            if !s.replayed {
                s.replayed = true;
                if let Some(after) = s.last_id {
                    let rows = s.db.inbox_after(after, 500).await.unwrap_or_default();
                    for row in &rows {
                        let item = inbox_item_json(row);
                        let ev = match row.channel {
                            Channel::Sms => Event::message(item),
                            Channel::Mms => Event::mms(item),
                        };
                        s.queue.push_back(sse_payload(&ev));
                    }
                }
                if let Some(ev) = s.queue.pop_front() {
                    return Some((Ok(ev), s));
                }
            }
            match s.rx.recv().await {
                Ok(ev) => Some((Ok(sse_payload(&ev)), s)),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(target: "cellmatik::sse", skipped = n, "sse subscriber lagged");
                    let hb = axum::response::sse::Event::default().comment("lagged");
                    Some((Ok(hb), s))
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
            }
        },
    )
}
