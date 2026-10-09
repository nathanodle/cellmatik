//! HTTP surface (spec §3): every endpoint, bearer auth, SSE with replay,
//! WS upgrade. Handlers stay thin — shaping happens in envelope.rs,
//! business in db/modem/voice/mms.
//!
//! Endpoint table (spec §3) — all bearer-authed except /healthz:
//!   /healthz, /v1/status, /v1/sms (POST/GET, GET {id}), /v1/messages
//!   (GET, {id}/read, DELETE {id}), /v1/webhook (GET/PUT/DELETE),
//!   /v1/events (SSE + Last-Event-ID replay), /v1/calls (POST/GET, {id},
//!   answer/hangup/dtmf/audio-WS), /v1/mms (POST/GET, {id}),
//!   /v1/media/{id} (raw bytes).
//!
//! SECURITY (spec §7): tokens only in the Authorization header (never
//! query strings — SSE and the WS upgrade authenticate on the upgrade
//! request); no CORS; no raw anyhow leaks (500 is {"error":"internal"});
//! 16 MiB body limit; handlers never log bodies; all inputs via serde
//! typed structs.

use crate::config::Config;
use crate::db::Db;
use crate::envelope::{self, EventBus, inbox_item_json, mms_item_json, sms_item_json, status_json};
use crate::modem::Modem;
use crate::mms::{Mms, MmsSendRequest};
use crate::tokens;
use crate::types::*;
use crate::voice::Voice;
use crate::wwan::Wwan;
use axum::extract::{ws::WebSocketUpgrade, DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response, Sse};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

pub struct AppState {
    pub db: Db,
    pub modem: Modem,
    pub voice: Voice,
    pub mms: Mms,
    pub wwan: Wwan,
    pub cfg: Arc<Config>,
    pub events: EventBus,
    pub started: std::time::Instant,
}

pub type SharedState = Arc<AppState>;

/// The full router (spec §3 endpoint table). main.rs calls
/// axum::serve on it.
pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(get_status))
        .route("/v1/sms", get(list_sms).post(post_sms))
        .route("/v1/sms/{id}", get(get_sms))
        .route("/v1/messages", get(list_messages))
        .route("/v1/messages/{id}/read", post(read_message))
        .route("/v1/messages/{id}", delete(delete_message))
        .route("/v1/webhook", get(get_webhook).put(put_webhook).delete(delete_webhook))
        .route("/v1/events", get(sse_events))
        .route("/v1/calls", get(list_calls).post(post_call))
        .route("/v1/calls/{id}", get(get_call))
        .route("/v1/calls/{id}/answer", post(answer_call))
        .route("/v1/calls/{id}/hangup", post(hangup_call))
        .route("/v1/calls/{id}/dtmf", post(dtmf_call))
        .route("/v1/calls/{id}/audio", get(ws_audio))
        .route("/v1/mms", get(list_mms).post(post_mms))
        .route("/v1/mms/{id}", get(get_mms))
        .route("/v1/media/{id}", get(get_media))
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_mw,
        ))
        .with_state(state)
}

// ===== auth ================================================================

/// Bearer auth on everything except /healthz. 401 (not 403) for
/// missing/bad/revoked tokens.
async fn auth_mw(
    State(state): State<SharedState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, ApiError> {
    if req.uri().path() != "/healthz" {
        let auth = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = auth.strip_prefix("Bearer ").unwrap_or("");
        let token = token.trim();
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::unauthorized());
        }
        let client = state
            .db
            .client_by_token_hash(&tokens::sha256_hex(token))
            .await
            .ok_or_else(ApiError::unauthorized)?;
        req.extensions_mut().insert(client);
    }
    Ok(next.run(req).await)
}

// ===== liveness / status ===================================================

async fn healthz(State(state): State<SharedState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "uptime_s": state.started.elapsed().as_secs(),
    }))
}

async fn get_status(State(state): State<SharedState>) -> Result<Json<serde_json::Value>, ApiError> {
    let snapshot = state.modem.snapshot().await;
    let bearer = state.wwan.state().await.bearer().to_string();
    Ok(Json(status_json(&snapshot, &state.db, &state.cfg, &bearer).await))
}

// ===== sms =================================================================

#[derive(Deserialize)]
struct SmsPost {
    to: String,
    text: String,
    delivery_report: Option<bool>,
}

#[derive(Deserialize)]
struct StatusFilter {
    status: Option<String>,
}

fn parse_status(s: &Option<String>) -> Result<Option<TransportStatus>, ApiError> {
    match s.as_deref() {
        None | Some("") => Ok(None),
        Some("pending") => Ok(Some(TransportStatus::Pending)),
        Some("delivered") => Ok(Some(TransportStatus::Delivered)),
        Some("failed") => Ok(Some(TransportStatus::Failed)),
        Some(_) => Err(ApiError::unprocessable(serde_json::json!({
            "error": "invalid_status"
        }))),
    }
}

/// POST /v1/sms — queue an outbound SMS (202 with the full item shape).
async fn post_sms(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Json(body): Json<SmsPost>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let cfg = &state.cfg;
    let to = crate::pdu::e164(&body.to).map_err(|_| {
        ApiError::unprocessable(serde_json::json!({ "error": "malformed", "field": "to" }))
    })?;
    let segments = crate::pdu::split_septets(&body.text, cfg.max_segments)
        .map_err(|e| ApiError::unprocessable(e.to_json()))?;
    if state.db.pending_outbox_count().await.map_err(|e| ApiError::internal(&e))? >= cfg.queue_limit as i64 {
        return Err(ApiError::service("queue_full", None));
    }
    let want_dr = body.delivery_report.unwrap_or(cfg.default_delivery_report);
    let vp = crate::pdu::validity_seconds(cfg.csmp_vp);
    let vp_deadline = crate::db::ts_plus(vp as i64);
    let row = state
        .db
        .queue_sms(client.id, &to, &body.text, want_dr, segments.len() as i64, vp_deadline)
        .await
        .map_err(|e| ApiError::internal(&e))?;
    Ok((StatusCode::ACCEPTED, Json(sms_item_json(&row, cfg))))
}

async fn list_sms(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Query(f): Query<StatusFilter>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let status = parse_status(&f.status)?;
    let rows = state
        .db
        .list_outbox(Some(client.id), status)
        .await
        .map_err(|e| ApiError::internal(&e))?;
    let items: Vec<_> = rows.iter().map(|r| sms_item_json(r, &state.cfg)).collect();
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn get_sms(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = state
        .db
        .get_outbox_scoped(id, client.id)
        .await
        .map_err(|e| ApiError::internal(&e))?
        .ok_or_else(|| ApiError::not_found("sms"))?;
    Ok(Json(sms_item_json(&row, &state.cfg)))
}

// ===== inbox (shared) ======================================================

#[derive(Deserialize)]
struct MessagesQuery {
    since: Option<i64>,
    unread: Option<bool>,
    limit: Option<i64>,
}

async fn list_messages(
    State(state): State<SharedState>,
    Query(q): Query<MessagesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let rows = state
        .db
        .list_inbox(q.since, q.unread.unwrap_or(false), limit)
        .await
        .map_err(|e| ApiError::internal(&e))?;
    let messages: Vec<_> = rows.iter().map(inbox_item_json).collect();
    Ok(Json(serde_json::json!({ "messages": messages })))
}

async fn read_message(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = state
        .db
        .mark_inbox_read(id)
        .await
        .map_err(|e| ApiError::internal(&e))?
        .ok_or_else(|| ApiError::not_found("message"))?;
    Ok(Json(inbox_item_json(&row)))
}

async fn delete_message(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let gone = state
        .db
        .delete_inbox(id)
        .await
        .map_err(|e| ApiError::internal(&e))?;
    if gone {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("message"))
    }
}

// ===== webhook =============================================================

async fn get_webhook(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
) -> Result<Json<serde_json::Value>, ApiError> {
    match state.db.get_webhook(client.id).await {
        Some(w) => Ok(Json(serde_json::json!({
            "url": w.url,
            "failing": w.failing,
            "last_error": w.last_error,
            "last_ok": w.last_ok,
        }))),
        None => Err(ApiError::not_found("webhook")),
    }
}

#[derive(Deserialize)]
struct WebhookPut {
    url: String,
}

/// PUT /v1/webhook — validates the URL is http(s)://, generates a fresh
/// 256-bit secret (shown once, never stored in the clear... it IS stored
/// for HMAC signing, but never returned again).
async fn put_webhook(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Json(body): Json<WebhookPut>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let url = body.url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) || url.len() > 512 {
        return Err(ApiError::unprocessable(serde_json::json!({
            "error": "invalid_url"
        })));
    }
    let secret = tokens::generate_token();
    state
        .db
        .set_webhook(client.id, url, &secret)
        .await
        .map_err(|e| ApiError::internal(&e))?;
    Ok(Json(serde_json::json!({ "url": url, "secret": secret })))
}

async fn delete_webhook(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
) -> Result<StatusCode, ApiError> {
    state
        .db
        .clear_webhook(client.id)
        .await
        .map_err(|e| ApiError::internal(&e))?;
    Ok(StatusCode::NO_CONTENT)
}

// ===== SSE =================================================================

async fn sse_events(
    State(state): State<SharedState>,
    Extension(_client): Extension<ClientRow>,
    headers: HeaderMap,
) -> Sse<impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>> + Send + 'static> {
    let last_id = headers
        .get("Last-Event-ID")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<i64>().ok());
    let stream = envelope::sse_stream(state.db.clone(), state.events.clone(), state.cfg.clone(), last_id);
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(state.cfg.heartbeat_s.max(1)))
            .text("keep-alive"),
    )
}

// ===== calls ===============================================================

#[derive(Deserialize)]
struct CallPost {
    to: String,
    audio: Option<bool>,
    hangup_after_s: Option<i64>,
}

async fn post_call(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Json(body): Json<CallPost>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let row = state
        .voice
        .originate(client.id, &body.to, body.audio.unwrap_or(true), body.hangup_after_s)
        .await?;
    let owner = state.db.client_name(row.client_id).await;
    Ok((StatusCode::ACCEPTED, Json(envelope::call_item_json(&row, owner.as_deref()))))
}

async fn list_calls(
    State(state): State<SharedState>,
    Query(f): Query<CallListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let status = match f.status.as_deref() {
        None | Some("") => None,
        Some("incoming") => Some(CallStatus::Incoming),
        Some("dialing") => Some(CallStatus::Dialing),
        Some("active") => Some(CallStatus::Active),
        Some("ended") => Some(CallStatus::Ended),
        Some(_) => {
            return Err(ApiError::unprocessable(serde_json::json!({
                "error": "invalid_status"
            })))
        }
    };
    let rows = state
        .db
        .list_calls(status, f.since)
        .await
        .map_err(|e| ApiError::internal(&e))?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let owner = state.db.client_name(row.client_id).await;
        items.push(envelope::call_item_json(row, owner.as_deref()));
    }
    Ok(Json(serde_json::json!({ "items": items })))
}

#[derive(Deserialize)]
struct CallListQuery {
    status: Option<String>,
    since: Option<String>,
}

async fn get_call(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = state
        .db
        .get_call(id)
        .await
        .map_err(|e| ApiError::internal(&e))?
        .ok_or_else(|| ApiError::not_found("call"))?;
    let owner = state.db.client_name(row.client_id).await;
    Ok(Json(envelope::call_item_json(&row, owner.as_deref())))
}

async fn answer_call(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = state.voice.answer(id, client.id).await?;
    let owner = state.db.client_name(row.client_id).await;
    Ok(Json(envelope::call_item_json(&row, owner.as_deref())))
}

async fn hangup_call(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = state.voice.hangup(id, client.id).await?;
    let owner = state.db.client_name(row.client_id).await;
    Ok(Json(envelope::call_item_json(&row, owner.as_deref())))
}

#[derive(Deserialize)]
struct DtmfPost {
    digits: String,
}

async fn dtmf_call(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    Json(body): Json<DtmfPost>,
) -> Result<StatusCode, ApiError> {
    state.voice.dtmf(id, &body.digits).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn ws_audio(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Path(id): Path<i64>,
    ws: WebSocketUpgrade,
) -> Response {
    let voice = state.voice.clone();
    let client_id = client.id;
    ws.on_upgrade(move |socket| {
        let voice = voice;
        async move { voice.attach_ws(id, client_id, socket).await }
    })
}

// ===== mms / media =========================================================

async fn post_mms(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Json(body): Json<MmsPostBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let row = state
        .mms
        .queue(client.id, MmsSendRequest { to: body.to, text: body.text, image_b64: body.image_b64 })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(mms_item_json(&row))))
}

#[derive(Deserialize)]
struct MmsPostBody {
    to: String,
    text: Option<String>,
    image_b64: String,
}

async fn list_mms(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Query(f): Query<MmsStatusQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let status = match f.status.as_deref() {
        None | Some("") => None,
        Some("pending") => Some(MmsStatus::Queued),
        Some("sending") => Some(MmsStatus::Sending),
        Some("retrying") => Some(MmsStatus::Retrying),
        Some("sent") => Some(MmsStatus::Sent),
        Some("delivered") => Some(MmsStatus::Delivered),
        Some("failed") => Some(MmsStatus::Failed),
        Some(_) => {
            return Err(ApiError::unprocessable(serde_json::json!({
                "error": "invalid_status"
            })))
        }
    };
    let rows = state.mms.list(client.id, status).await?;
    let items: Vec<_> = rows.iter().map(mms_item_json).collect();
    Ok(Json(serde_json::json!({ "items": items })))
}

#[derive(Deserialize)]
struct MmsStatusQuery {
    status: Option<String>,
}

async fn get_mms(
    State(state): State<SharedState>,
    Extension(client): Extension<ClientRow>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = state.mms.get(id, client.id).await?;
    Ok(Json(mms_item_json(&row)))
}

async fn get_media(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let (row, bytes) = state
        .db
        .get_media(id)
        .await
        .map_err(|e| ApiError::internal(&e))?
        .ok_or_else(|| ApiError::not_found("media"))?;
    Response::builder()
        .header(header::CONTENT_TYPE, row.content_type)
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(axum::body::Body::from(bytes))
        .map_err(|e| ApiError::internal(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_filter_parsing() {
        assert!(matches!(parse_status(&None), Ok(None)));
        assert!(matches!(parse_status(&Some("pending".into())), Ok(Some(TransportStatus::Pending))));
        assert!(parse_status(&Some("bogus".into())).is_err());
    }

    #[test]
    fn ts_plus_shape() {
        let t = crate::db::ts_plus(60);
        assert!(t.ends_with('Z') && t.len() == 24);
    }
}
