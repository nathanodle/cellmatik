//! Shared domain types — the frozen contract between every module.
//!
//! Row structs mirror the SQLite schema (spec §4). Enum→column mapping is
//! lowercase-string serde. Security rules (spec §7) apply to all of it:
//! no panics on derived data, checked arithmetic, opaque errors to clients.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{json, Value};

pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

// ===== auth / errors ======================================================

pub type ApiResult<T> = Result<T, ApiError>;

/// Typed, opaque client-facing error. `body` is always a documented JSON
/// shape — never internal detail (spec §7).
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub body: Value,
}

impl ApiError {
    pub fn unauthorized() -> Self {
        Self { status: 401, body: json!({"error": "unauthorized"}) }
    }
    pub fn forbidden() -> Self {
        Self { status: 403, body: json!({"error": "forbidden"}) }
    }
    pub fn not_found(what: &str) -> Self {
        Self { status: 404, body: json!({"error": "not_found", "what": what}) }
    }
    pub fn conflict(error: &str) -> Self {
        Self { status: 409, body: json!({"error": error}) }
    }
    /// 422 with a diagnostic body, e.g. `{"error":"too_long","chars":1700,…}`.
    pub fn unprocessable(body: Value) -> Self {
        Self { status: 422, body }
    }
    pub fn service(error: &str, detail: Option<&str>) -> Self {
        let body = match detail {
            Some(d) => json!({"error": error, "detail": d}),
            None => json!({"error": error}),
        };
        Self { status: 503, body }
    }
    pub fn internal(err: &dyn std::fmt::Display) -> Self {
        tracing::error!(target: "cellmatik::api", error = %err, "internal error");
        Self { status: 500, body: json!({"error": "internal"}) }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut r = (status, axum::Json(self.body)).into_response();
        // 401 must advertise the scheme for standard clients.
        if self.status == 401 {
            if let Ok(hv) = axum::http::HeaderValue::from_str("Bearer") {
                r.headers_mut().insert("WWW-Authenticate", hv);
            }
        }
        r
    }
}

// ===== channel / status enums ============================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Sms,
    Mms,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Sms => "sms",
            Channel::Mms => "mms",
        }
    }
}

/// Stored transport status for `outbox` and `outbox_segments` (spec §4:
/// `pending|delivered|failed` only — detail is derived, never stored).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportStatus {
    Pending,
    Delivered,
    Failed,
}

impl TransportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportStatus::Pending => "pending",
            TransportStatus::Delivered => "delivered",
            TransportStatus::Failed => "failed",
        }
    }
}

/// Derived `detail` for a pending outbox row (spec §3 status model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingDetail {
    Queued,
    Retrying,
    Submitted,
    Stale,
}

/// Stored MMS outbox status (spec §3 MMS); `Sending`/`Retrying` surface as
/// `pending` + detail in the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MmsStatus {
    #[serde(rename = "pending")]
    Queued,
    Sending,
    Retrying,
    Sent,
    Delivered,
    Failed,
}

impl MmsStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            MmsStatus::Queued => "pending",
            MmsStatus::Sending => "sending",
            MmsStatus::Retrying => "retrying",
            MmsStatus::Sent => "sent",
            MmsStatus::Delivered => "delivered",
            MmsStatus::Failed => "failed",
        }
    }
}

impl std::fmt::Display for MmsStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MmsDetail {
    Queued,
    Sending,
    Retrying,
}

/// Content-fetch state of an inbound MMS (spec §3: never-silent breadcrumb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FetchState {
    Ok,
    Unfetchable,
}

impl FetchState {
    pub fn as_str(self) -> &'static str {
        match self {
            FetchState::Ok => "ok",
            FetchState::Unfetchable => "unfetchable",
        }
    }
}

// ===== rows ===============================================================

#[derive(Debug, Clone, Serialize)]
pub struct ClientRow {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookRow {
    pub client_id: i64,
    pub url: String,
    pub secret: String,
    pub failing: bool,
    pub last_error: Option<String>,
    pub last_ok: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboxRow {
    pub id: i64,
    pub client_id: i64,
    pub to_num: String,
    pub text: String,
    pub want_dr: bool,
    pub status: TransportStatus,
    pub attempts: i64,
    pub created_at: String,
    pub submitted_at: Option<String>,
    pub delivered_at: Option<String>,
    pub error: Option<String>,
    /// VP-decoded absolute deadline; at expiry → `failed/no_delivery_report`
    /// (spec §3/§5).
    pub vp_deadline: String,
    pub segments: Vec<SegmentRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentRow {
    pub outbox_id: i64,
    pub seg_index: i64,
    pub mr: Option<i64>,
    pub status: TransportStatus,
    pub error: Option<String>,
    pub delivered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InboxRow {
    pub id: i64,
    pub sender: String,
    pub channel: Channel,
    pub text: String,
    pub fetch: Option<FetchState>,
    pub media: Vec<MediaRow>,
    pub received_at: String,
    pub read: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MediaRow {
    pub id: i64,
    pub inbox_id: Option<i64>,
    pub name: String,
    #[serde(rename = "type")]
    pub content_type: String,
    pub bytes: i64,
    /// Server-side path — never serialized to API items (envelope strips it).
    pub path: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[serde(rename = "in")]
    In,
    #[serde(rename = "out")]
    Out,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CallStatus {
    Incoming,
    Dialing,
    Active,
    Ended,
}

impl CallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CallStatus::Incoming => "incoming",
            CallStatus::Dialing => "dialing",
            CallStatus::Active => "active",
            CallStatus::Ended => "ended",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CallRow {
    pub id: i64,
    pub client_id: i64,
    pub direction: Direction,
    pub remote: String,
    pub status: CallStatus,
    pub cause: Option<String>,
    pub audio: bool,
    pub hangup_after_s: Option<i64>,
    pub created_at: String,
    pub active_at: Option<String>,
    pub ended_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MmsOutboxRow {
    pub id: i64,
    pub client_id: i64,
    pub to_num: String,
    pub text: Option<String>,
    pub media: MediaRow,
    pub status: MmsStatus,
    pub error: Option<String>,
    pub created_at: String,
    pub sent_at: Option<String>,
}

// ===== derived status helpers ============================================

/// Derive `detail` for a pending outbox row (spec §3): queued = nothing
/// submitted; retrying = attempts burned but nothing submitted; submitted =
/// any segment has an mr; stale = submitted longer than `stale_after_s`.
/// Never panics, never trusts stored timestamps beyond parsing.
pub fn outbox_detail(row: &OutboxRow, stale_after_s: u64) -> Option<PendingDetail> {
    if row.status != TransportStatus::Pending {
        return None;
    }
    let submitted = row.segments.iter().any(|s| s.mr.is_some());
    if !submitted {
        return Some(if row.attempts > 0 {
            PendingDetail::Retrying
        } else {
            PendingDetail::Queued
        });
    }
    let stale = row
        .submitted_at
        .as_deref()
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|t| {
            let age = (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds();
            age > 0 && (age as u64) > stale_after_s
        })
        .unwrap_or(true);
    Some(if stale { PendingDetail::Stale } else { PendingDetail::Submitted })
}

/// Poll hint for pending rows (spec §3): ~2 s fresh-queued, 30 s fresh,
/// growing 30 → 60 → 120 → 300 as it ages.
pub fn check_after_s(row: &OutboxRow, stale_after_s: u64) -> u64 {
    use PendingDetail::*;
    match outbox_detail(row, stale_after_s) {
        Some(Queued) | Some(Retrying) => 2,
        Some(Submitted) => {
            let age = row
                .submitted_at
                .as_deref()
                .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
                .map(|t| {
                    let age = (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds();
                    age.max(0) as u64
                })
                .unwrap_or(stale_after_s);
            match age {
                a if a < 120 => 30,
                a if a < 240 => 60,
                a if a < 480 => 120,
                _ => 300,
            }
        }
        Some(Stale) => 300,
        None => 300, // terminal — clients stop polling anyway
    }
}

/// `retryable` for failed rows (spec §3): outcome-unknown and transient
/// causes say true; carrier rejection is final.
pub fn retryable(error: &str) -> bool {
    matches!(
        error,
        "network_timeout"
            | "no_network_service"
            | "congestion"
            | "expired"
            | "no_delivery_report"
            | "submit_timeout"
            | "mms_unavailable"
            | "send_timeout"
    )
}

/// MMS pending-detail derivation (spec §3 MMS).
pub fn mms_detail(row: &MmsOutboxRow) -> Option<MmsDetail> {
    match row.status {
        MmsStatus::Queued => Some(MmsDetail::Queued),
        MmsStatus::Sending => Some(MmsDetail::Sending),
        MmsStatus::Retrying => Some(MmsDetail::Retrying),
        _ => None,
    }
}

// ===== modem / status =====================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ModemState {
    Probing,
    Ready,
    Recovering,
    Unresponsive,
}

impl ModemState {
    pub fn as_str(self) -> &'static str {
        match self {
            ModemState::Probing => "probing",
            ModemState::Ready => "ready",
            ModemState::Recovering => "recovering",
            ModemState::Unresponsive => "unresponsive",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ModemInfo {
    pub model: String,
    pub fw: String,
    pub state: Option<ModemState>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SimInfo {
    pub iccid: String,
    pub msisdn: String,
    pub state: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NetworkInfo {
    pub operator: String,
    pub rat: String,
    pub band: String,
    pub csq: i64,
    pub registered: bool,
}

/// Live modem-side snapshot; `/v1/status` composes this with db-derived
/// sms/mms fields (envelope::status_json).
#[derive(Debug, Clone, Default, Serialize)]
pub struct ModemSnapshot {
    pub modem: ModemInfo,
    pub sim: SimInfo,
    pub network: NetworkInfo,
}

// ===== events =============================================================

/// Typed push event (spec §3 envelope). `inbox_id` present ⇒ SSE carries
/// `id:` for replay; call/dtmf/modem events are live-only.
#[derive(Debug, Clone)]
pub struct Event {
    pub kind: &'static str,
    pub inbox_id: Option<i64>,
    pub data: Value,
}

impl Event {
    pub fn message(item: Value) -> Self {
        Self { kind: "message", inbox_id: item.get("id").and_then(|v| v.as_i64()), data: item }
    }
    pub fn mms(item: Value) -> Self {
        Self { kind: "mms", inbox_id: item.get("id").and_then(|v| v.as_i64()), data: item }
    }
    pub fn call_incoming(item: Value) -> Self {
        Self { kind: "call_incoming", inbox_id: None, data: item }
    }
    pub fn call_state(item: Value) -> Self {
        Self { kind: "call_state", inbox_id: None, data: item }
    }
    pub fn dtmf(item: Value) -> Self {
        Self { kind: "dtmf", inbox_id: None, data: item }
    }
    pub fn modem_state(item: Value) -> Self {
        Self { kind: "modem_state", inbox_id: None, data: item }
    }
}
