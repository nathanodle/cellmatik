//! Call state machine + WS audio bridge (spec §3 Voice). All AT goes
//! through modem::Modem::at (queue-serialized); lifecycle URCs arrive on
//! the URC subscription this service holds.
//!
//! CONTRACT (implemented per spec §3):
//!  - Modem profile without voice (rm520n) ⇒ every voice endpoint fails
//!    `ApiError::service("voice_unsupported", None)`; no ATD ever issued.
//!  - Outbound: `POST /v1/calls` → insert row (direction out, status
//!    dialing) + `ATD<e164>;` (async OK). URC `VOICE CALL: BEGIN` →
//!    transition dialing→active (active_at stamp) + `call_state` event.
//!    `NO CARRIER`/`VOICE CALL: END` during dialing → busy/no_answer
//!    causes per observed URC detail; during active → remote_hangup.
//!  - Inbound: `+CLIP` (with RING) → insert row (direction in, status
//!    incoming, attributed to the bootstrap owner client) +
//!    `call_incoming` event. First `POST /answer` wins via
//!    `db.transition_call(expected=Incoming, next=Active)` row-count —
//!    losers get 409 (atomic claim, spec §7). `ATA` issued on the winning
//!    claim. Ring-out at `ring_timeout_s` → ended/missed + event.
//!  - Hangup: owner-only (403 otherwise) → `AT+CHUP` → transition
//!    active→ended, cause normal + `call_state` event.
//!  - `hangup_after_s`: paging (audio=false) calls hang up after the
//!    timer with cause `max_duration`. `audio=false` without
//!    `hangup_after_s` → 422 (enforced here too — defense in depth).
//!  - `max_call_duration_s` safety cap on every call.
//!  - DTMF out: `AT+VTS=<digit>` per digit (queue-serialized by the modem
//!    engine). Inbound: `+DTMF` URCs → `dtmf` envelope events (when
//!    `dtmf_detection`).
//!  - Audio WS (`attach_ws`): one live attach per call (second attach →
//!    close 1008 already_attached, atomic claim). Binary frames = g711u
//!    samples, `audio_frame_ms` per frame (20 ms = 160 bytes @ 8 kHz),
//!    full duplex. Client frames before `active` are dropped. Losing the
//!    socket while active for > `audio_grace_s` → CHUP + cause
//!    audio_lost. Reconnect inside the window reattaches. Call end closes
//!    the WS with code 1000, reason `call_ended`.
//!  - Audio bridge: cpal (feature `audio`) default input+output devices
//!    at 8 kHz mono S16LE ↔ g711u both directions; streams run only while
//!    ≥1 socket is attached. Without the feature, originate(audio=true)
//!    and attach fail `audio_unavailable`; paging is fully functional.
//!  - g711u: standard µ-law codec implemented here — no external crate.
//!
//! SECURITY (spec §7): no unwrap on WS frames (length-checked frames
//! tolerated: malformed dropped, never panic); DTMF digits validated
//! ([0-9A-D*#]) before AT; audio buffers bounded (frame channels cap at
//! ~1 s; overflow drops, never queues unbounded). No unsafe here.

use crate::db::Db;
use crate::envelope::{call_item_json, EventBus};
use crate::modem::{Modem, Urc};
use crate::types::*;
use axum::extract::ws::WebSocket;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::mpsc;

// ===== g711u (ITU-T G.711 µ-law) ===========================================

const ULAW_BIAS: i32 = 132;

/// S16LE → µ-law octet (used by the audio engine and tests). Total: any
/// i16 maps to a byte.
#[cfg(any(test, feature = "audio"))]
pub fn g711u_encode(s: i16) -> u8 {
    let sign: u8 = if s < 0 { 0x80 } else { 0x00 };
    let mut v: i32 = i32::from(s);
    if v < 0 {
        v = -v;
    }
    if v > 32635 {
        v = 32635;
    }
    v += ULAW_BIAS;
    // segment exponent: v ∈ [132, 32767] ⇒ lz ∈ [17, 24] ⇒ exp ∈ [0, 7]
    let exp = 24u32.saturating_sub((v as u32).leading_zeros());
    let mantissa = ((v >> (exp + 3)) & 0x0F) as u8;
    !(sign | ((exp as u8) << 4) | mantissa)
}

/// µ-law octet → S16LE (standard 13-bit reconstruction).
pub fn g711u_decode(u: u8) -> i16 {
    let u = !u;
    let sign = u & 0x80;
    let exp = i32::from((u >> 4) & 0x07);
    let mant = i32::from(u & 0x0F);
    let mut v = ((mant << 3) + ULAW_BIAS) << exp;
    v -= ULAW_BIAS;
    if sign != 0 {
        v = -v;
    }
    v as i16
}

#[cfg(any(test, feature = "audio"))]
fn encode_frame(samples: &[i16]) -> Vec<u8> {
    samples.iter().map(|&s| g711u_encode(s)).collect()
}

fn decode_frame(bytes: &[u8]) -> Vec<i16> {
    bytes.iter().map(|&b| g711u_decode(b)).collect()
}

/// Valid DTMF digit set (AT+VTS argument domain).
fn valid_digits(digits: &str) -> bool {
    !digits.is_empty()
        && digits.chars().all(|c| matches!(c, '0'..='9' | 'A'..='D' | 'a'..='d' | '*' | '#'))
        && digits.len() <= 32
}

// ===== service =============================================================

#[derive(Debug, Clone)]
pub struct VoiceCfg {
    /// ALSA name of the USB adapter; audio feature only.
    #[cfg(feature = "audio")]
    pub audio_device: String,
    #[cfg(feature = "audio")]
    pub audio_frame_ms: u32,
    pub audio_grace_s: u64,
    pub ring_timeout_s: u64,
    pub max_call_duration_s: u64,
    pub dtmf_detection: bool,
    pub voice_supported: bool,
}

/// One live WS attach: engine→client frame channel + client→speaker queue.
/// The queue plumbing is read by the audio engine; without the `audio`
/// feature the struct still anchors the single-attach claim.
struct Attach {
    #[cfg(feature = "audio")]
    sink: mpsc::Sender<axum::extract::ws::Message>,
    #[cfg(feature = "audio")]
    spk: Arc<StdMutex<VecDeque<Vec<i16>>>>,
}

const SPK_QUEUE_CAP: usize = 50; // ~1 s of 20 ms frames
const FRAME_CHANNEL_CAP: usize = 50;

struct VoiceInner {
    modem: Modem,
    db: Db,
    events: EventBus,
    cfg: VoiceCfg,
    attaches: Arc<StdMutex<HashMap<i64, Attach>>>,
    #[cfg(feature = "audio")]
    audio: StdMutex<Option<AudioEngine>>,
}

#[derive(Clone)]
pub struct Voice {
    inner: Arc<VoiceInner>,
}

impl Voice {
    /// Spawn the URC subscription loop (ring/clip/det/carrier watchers).
    pub fn spawn(modem: Modem, db: Db, events: EventBus, cfg: VoiceCfg) -> Voice {
        let inner = Arc::new(VoiceInner {
            modem,
            db,
            events,
            cfg,
            attaches: Arc::new(StdMutex::new(HashMap::new())),
            #[cfg(feature = "audio")]
            audio: StdMutex::new(None),
        });
        let urc_inner = inner.clone();
        tokio::spawn(async move {
            let mut urcs = urc_inner.modem.urc_subscribe();
            loop {
                match urcs.recv().await {
                    Ok(Urc::Clip { number }) => handle_clip(&urc_inner, number).await,
                    Ok(Urc::VoiceCallBegin) => handle_begin(&urc_inner).await,
                    Ok(Urc::VoiceCallEnd) => handle_end(&urc_inner, None, false).await,
                    Ok(Urc::NoCarrier { cause }) => handle_end(&urc_inner, cause, true).await,
                    Ok(Urc::Dtmf { digits }) => handle_dtmf_in(&urc_inner, digits).await,
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "voice urc lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Voice { inner }
    }

    fn unsupported() -> ApiError {
        ApiError::service("voice_unsupported", None)
    }
}

// ===== URC-driven lifecycle ================================================

async fn publish_call(inner: &VoiceInner, row: &CallRow, incoming: bool) {
    let owner = inner.db.client_name(row.client_id).await;
    let item = call_item_json(row, owner.as_deref());
    let ev = if incoming { Event::call_incoming(item) } else { Event::call_state(item) };
    inner.events.publish(ev);
}

async fn newest_call(inner: &VoiceInner, status: CallStatus) -> Option<CallRow> {
    match inner.db.list_calls(Some(status), None).await {
        Ok(rows) => rows.into_iter().next(), // list is id DESC
        Err(e) => {
            tracing::error!(error = %e, "call list failed");
            None
        }
    }
}

/// +CLIP: first sighting of an inbound call inserts the row + event; later
/// CLIPs for the same (still incoming) call are ignored.
async fn handle_clip(inner: &Arc<VoiceInner>, number: String) {
    if !inner.cfg.voice_supported || number.is_empty() {
        return;
    }
    if let Some(existing) = newest_call(inner, CallStatus::Incoming).await {
        if existing.direction == Direction::In {
            tracing::debug!(call = existing.id, "repeat clip for live incoming call");
            return;
        }
    }
    let Some(client_id) = inner.db.first_client_id().await else {
        tracing::warn!("no client rows; inbound call not recorded");
        return;
    };
    let remote = format!("+{}", number.trim_start_matches('+'));
    let row = match inner.db.insert_call(client_id, Direction::In, &remote, true, None).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "incoming call insert failed");
            return;
        }
    };
    tracing::info!(call = row.id, from = %remote, "incoming call");
    publish_call(inner, &row, true).await;
    spawn_ring_watch(inner.clone(), row.id);
}

/// VOICE CALL: BEGIN — dialing→active.
async fn handle_begin(inner: &Arc<VoiceInner>) {
    let Some(row) = newest_call(inner, CallStatus::Dialing).await else {
        return; // answered inbound already transitioned; stray BEGIN ignored
    };
    match inner
        .db
        .transition_call(row.id, CallStatus::Dialing, CallStatus::Active, None)
        .await
    {
        Ok(Some(active)) => {
            tracing::info!(call = active.id, "call active");
            publish_call(inner, &active, false).await;
            spawn_duration_watch(inner.clone(), active.id);
        }
        _ => {}
    }
}

/// End-of-call URC. `carrier_lost` distinguishes NO CARRIER/+CEND (carries
/// a cause code) from VOICE CALL: END (remote hung up cleanly).
async fn handle_end(inner: &Arc<VoiceInner>, cause: Option<String>, carrier_lost: bool) {
    // active call ends first
    if let Some(row) = newest_call(inner, CallStatus::Active).await {
        let end_cause = if carrier_lost { map_cend_cause(cause.as_deref(), false) } else { "remote_hangup".to_string() };
        if let Ok(Some(ended)) = inner
            .db
            .transition_call(row.id, CallStatus::Active, CallStatus::Ended, Some(&end_cause))
            .await
        {
            tracing::info!(call = ended.id, cause = %end_cause, "call ended");
            publish_call(inner, &ended, false).await;
        }
        return;
    }
    // still dialing: the call never connected
    if let Some(row) = newest_call(inner, CallStatus::Dialing).await {
        let end_cause = map_cend_cause(cause.as_deref(), true);
        if let Ok(Some(ended)) = inner
            .db
            .transition_call(row.id, CallStatus::Dialing, CallStatus::Ended, Some(&end_cause))
            .await
        {
            tracing::info!(call = ended.id, cause = %end_cause, "outbound call failed");
            publish_call(inner, &ended, false).await;
        }
    }
}

/// SIMCom +CEND cause codes → spec cause table.
fn map_cend_cause(cause: Option<&str>, during_dialing: bool) -> String {
    match cause {
        Some("17") => "busy".into(),
        Some("16") | Some("19") | Some("21") if during_dialing => "no_answer".into(),
        Some(c) if during_dialing => format!("no_answer_{c}"),
        Some(c) => format!("remote_hangup_{c}"),
        None if during_dialing => "no_answer".into(),
        None => "remote_hangup".into(),
    }
}

/// +DTMF (DDET): publish when detection is enabled and a call is live.
async fn handle_dtmf_in(inner: &Arc<VoiceInner>, digits: String) {
    if !inner.cfg.dtmf_detection {
        return;
    }
    if let Some(row) = newest_call(inner, CallStatus::Active).await {
        let digits: String = digits.chars().filter(|c| valid_digits(&c.to_string())).take(16).collect();
        if digits.is_empty() {
            return;
        }
        inner
            .events
            .publish(Event::dtmf(serde_json::json!({ "call_id": row.id, "digits": digits })));
    }
}

// ===== watchdogs ===========================================================

fn spawn_ring_watch(inner: Arc<VoiceInner>, call_id: i64) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(inner.cfg.ring_timeout_s.max(1))).await;
        if let Ok(Some(row)) = inner.db.get_call(call_id).await {
            if row.status == CallStatus::Incoming {
                if let Ok(Some(ended)) = inner
                    .db
                    .transition_call(call_id, CallStatus::Incoming, CallStatus::Ended, Some("missed"))
                    .await
                {
                    publish_call(&inner, &ended, false).await;
                }
            }
        }
    });
}

fn spawn_dial_watch(inner: Arc<VoiceInner>, call_id: i64) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(inner.cfg.ring_timeout_s.max(1))).await;
        if let Ok(Some(row)) = inner.db.get_call(call_id).await {
            if row.status == CallStatus::Dialing {
                let _ = inner.modem.at("ATH", Duration::from_secs(5)).await;
                if let Ok(Some(ended)) = inner
                    .db
                    .transition_call(call_id, CallStatus::Dialing, CallStatus::Ended, Some("no_answer"))
                    .await
                {
                    publish_call(&inner, &ended, false).await;
                }
            }
        }
    });
}

fn spawn_duration_watch(inner: Arc<VoiceInner>, call_id: i64) {
    tokio::spawn(async move {
        let cap = inner.cfg.max_call_duration_s.max(1);
        let hangup_after = inner
            .db
            .get_call(call_id)
            .await
            .ok()
            .flatten()
            .and_then(|r| r.hangup_after_s)
            .map(|s| s.max(1) as u64)
            .unwrap_or(cap);
        tokio::time::sleep(Duration::from_secs(hangup_after.min(cap))).await;
        if let Ok(Some(row)) = inner.db.get_call(call_id).await {
            if row.status == CallStatus::Active {
                let _ = inner.modem.at("AT+CHUP", Duration::from_secs(5)).await;
                if let Ok(Some(ended)) = inner
                    .db
                    .transition_call(call_id, CallStatus::Active, CallStatus::Ended, Some("max_duration"))
                    .await
                {
                    publish_call(&inner, &ended, false).await;
                }
            }
        }
    });
}

// ===== public API ==========================================================

impl Voice {
    /// `POST /v1/calls` — 422 when audio=false && hangup_after_s is None.
    pub async fn originate(
        &self,
        client_id: i64,
        to: &str,
        audio: bool,
        hangup_after_s: Option<i64>,
    ) -> ApiResult<CallRow> {
        let inner = &self.inner;
        if !inner.cfg.voice_supported {
            return Err(Self::unsupported());
        }
        if audio && !cfg!(feature = "audio") {
            return Err(ApiError::service("audio_unavailable", None));
        }
        if !audio && hangup_after_s.is_none() {
            return Err(ApiError::unprocessable(serde_json::json!({
                "error": "hangup_after_s_required"
            })));
        }
        let to = crate::pdu::e164(to)
            .map_err(|_| ApiError::unprocessable(serde_json::json!({ "error": "invalid_to" })))?;
        let row = inner
            .db
            .insert_call(client_id, Direction::Out, &to, audio, hangup_after_s)
            .await
            .map_err(|e| ApiError::internal(&e))?;
        let cmd = format!("ATD{to};");
        match inner.modem.at(cmd, Duration::from_secs(10)).await {
            Ok(_) => {
                spawn_dial_watch(self.inner.clone(), row.id);
                Ok(row)
            }
            Err(e) => {
                if let Ok(Some(ended)) = inner
                    .db
                    .transition_call(row.id, CallStatus::Dialing, CallStatus::Ended, Some("failed"))
                    .await
                {
                    publish_call(inner, &ended, false).await;
                }
                Err(ApiError::service("dial_failed", Some(&e.to_string())))
            }
        }
    }

    /// `POST /v1/calls/{id}/answer` — first claimer wins, others 409.
    pub async fn answer(&self, call_id: i64, client_id: i64) -> ApiResult<CallRow> {
        let _ = client_id; // any authenticated client may answer (first wins)
        let inner = &self.inner;
        if !inner.cfg.voice_supported {
            return Err(Self::unsupported());
        }
        let row = inner
            .db
            .get_call(call_id)
            .await
            .map_err(|e| ApiError::internal(&e))?
            .ok_or_else(|| ApiError::not_found("call"))?;
        if row.direction != Direction::In || row.status != CallStatus::Incoming {
            return Err(ApiError::conflict("not_incoming"));
        }
        match inner
            .db
            .transition_call(call_id, CallStatus::Incoming, CallStatus::Active, None)
            .await
        {
            Ok(Some(won)) => {
                if inner.modem.at("ATA", Duration::from_secs(10)).await.is_err() {
                    if let Ok(Some(ended)) = inner
                        .db
                        .transition_call(call_id, CallStatus::Active, CallStatus::Ended, Some("answer_failed"))
                        .await
                    {
                        publish_call(inner, &ended, false).await;
                    }
                    return Err(ApiError::service("answer_failed", None));
                }
                publish_call(inner, &won, false).await;
                spawn_duration_watch(self.inner.clone(), call_id);
                Ok(won)
            }
            _ => Err(ApiError::conflict("already_answered")),
        }
    }

    /// `POST /v1/calls/{id}/hangup` — owner only (403).
    pub async fn hangup(&self, call_id: i64, client_id: i64) -> ApiResult<CallRow> {
        let inner = &self.inner;
        if !inner.cfg.voice_supported {
            return Err(Self::unsupported());
        }
        let row = inner
            .db
            .get_call(call_id)
            .await
            .map_err(|e| ApiError::internal(&e))?
            .ok_or_else(|| ApiError::not_found("call"))?;
        if row.client_id != client_id {
            return Err(ApiError::forbidden());
        }
        if row.status == CallStatus::Ended {
            return Err(ApiError::conflict("already_ended"));
        }
        if let Err(e) = inner.modem.at("AT+CHUP", Duration::from_secs(5)).await {
            tracing::warn!(error = %e, "CHUP failed (transitioning anyway)");
        }
        match inner
            .db
            .transition_call(call_id, row.status.clone(), CallStatus::Ended, Some("normal"))
            .await
        {
            Ok(Some(ended)) => {
                publish_call(inner, &ended, false).await;
                Ok(ended)
            }
            _ => Err(ApiError::conflict("already_ended")),
        }
    }

    /// `POST /v1/calls/{id}/dtmf` — digits validated [0-9A-D*#].
    pub async fn dtmf(&self, call_id: i64, digits: &str) -> ApiResult<()> {
        let inner = &self.inner;
        if !inner.cfg.voice_supported {
            return Err(Self::unsupported());
        }
        if !valid_digits(digits) {
            return Err(ApiError::unprocessable(serde_json::json!({
                "error": "invalid_digits"
            })));
        }
        let row = inner
            .db
            .get_call(call_id)
            .await
            .map_err(|e| ApiError::internal(&e))?
            .ok_or_else(|| ApiError::not_found("call"))?;
        if row.status != CallStatus::Active {
            return Err(ApiError::conflict("not_active"));
        }
        for d in digits.to_uppercase().chars() {
            if let Err(e) = inner.modem.at(format!("AT+VTS={d}"), Duration::from_secs(5)).await {
                return Err(ApiError::service("dtmf_failed", Some(&e.to_string())));
            }
        }
        Ok(())
    }

    /// `GET /v1/calls/{id}/audio` WS upgrade — one live attach per call
    /// (close 1008 already_attached on contest), g711u frame pump, grace
    /// timer, closes 1000 "call_ended". Client frames before `active` are
    /// dropped. Attach is not owner-scoped (calls are a shared dashboard
    /// view; the WS handshake already required a bearer token).
    pub async fn attach_ws(&self, call_id: i64, client_id: i64, socket: WebSocket) {
        use axum::extract::ws::{CloseFrame, Message};

        let inner = &self.inner;
        let _ = client_id;

        async fn close(mut socket: WebSocket, code: u16, reason: &'static str) {
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code,
                    reason: reason.into(),
                })))
                .await;
        }

        if !inner.cfg.voice_supported {
            close(socket, 1008, "voice_unsupported").await;
            return;
        }
        let row = match inner.db.get_call(call_id).await {
            Ok(Some(r)) => r,
            _ => {
                close(socket, 1008, "not_found").await;
                return;
            }
        };
        if row.status == CallStatus::Ended {
            close(socket, 1000, "call_ended").await;
            return;
        }
        if !row.audio {
            close(socket, 1008, "audio_disabled").await;
            return;
        }
        if start_engine(inner).is_err() {
            close(socket, 1008, "audio_unavailable").await;
            return;
        }

        // atomic claim of the single attach slot (guard never lives past
        // this block — no await while held)
        let spk = Arc::new(StdMutex::new(VecDeque::<Vec<i16>>::new()));
        let claim = {
            let mut map = lock_map(&inner.attaches);
            if map.contains_key(&call_id) {
                None
            } else {
                let (tx, rx) = mpsc::channel(FRAME_CHANNEL_CAP);
                map.insert(call_id, Attach {
                    #[cfg(feature = "audio")]
                    sink: tx,
                    #[cfg(feature = "audio")]
                    spk: spk.clone(),
                });
                #[cfg(not(feature = "audio"))]
                drop(tx); // no engine to own the sender end
                Some(rx)
            }
        };
        let Some(frame_rx) = claim else {
            close(socket, 1008, "already_attached").await;
            return;
        };
        Self::run_attach(
            self.inner.clone(),
            call_id,
            socket,
            frame_rx,
            spk,
            row.status == CallStatus::Active,
        )
        .await;
    }

    /// Frame pump: writer task (engine→client + call-end close), reader
    /// loop (client→speaker, dropped until active).
    async fn run_attach(
        inner: Arc<VoiceInner>,
        call_id: i64,
        socket: WebSocket,
        frame_rx: mpsc::Receiver<axum::extract::ws::Message>,
        spk: Arc<StdMutex<VecDeque<Vec<i16>>>>,
        started_active: bool,
    ) {
        use axum::extract::ws::{CloseFrame, Message};
        use futures_util::{SinkExt, StreamExt};

        let active = Arc::new(AtomicBool::new(started_active));
        let mut frame_rx = frame_rx;
        let mut ev_rx = inner.events.subscribe();
        let (mut sink, mut stream) = socket.split();

        let w_active = active.clone();
        let writer = tokio::spawn(async move {
            loop {
                tokio::select! {
                    maybe = frame_rx.recv() => {
                        match maybe {
                            Some(m) => {
                                if sink.send(m).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    ev = ev_rx.recv() => {
                        if let Ok(Event { kind: "call_state", data, .. }) = ev {
                            let id = data.get("id").and_then(|v| v.as_i64());
                            let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("");
                            if id == Some(call_id) {
                                if status == "active" {
                                    w_active.store(true, Ordering::SeqCst);
                                }
                                if status == "ended" {
                                    let _ = sink
                                        .send(Message::Close(Some(CloseFrame {
                                            code: 1000,
                                            reason: "call_ended".into(),
                                        })))
                                        .await;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        // reader: binary g711u frames → speaker queue (bounded)
        while let Some(Ok(msg)) = stream.next().await {
            if let Message::Binary(data) = msg {
                if !active.load(Ordering::SeqCst) {
                    continue; // frames before active are dropped
                }
                let mut q = spk.lock().unwrap_or_else(|e| e.into_inner());
                q.push_back(decode_frame(&data));
                while q.len() > SPK_QUEUE_CAP {
                    q.pop_front();
                }
            }
        }

        // socket gone: release the claim, maybe stop the engine, start the
        // audio-grace window
        {
            let mut map = lock_map(&inner.attaches);
            map.remove(&call_id);
        }
        writer.abort();
        #[cfg(feature = "audio")]
        maybe_stop_engine(&inner);
        spawn_audio_grace(inner.clone(), call_id);
    }
}

fn lock_map(map: &StdMutex<HashMap<i64, Attach>>) -> std::sync::MutexGuard<'_, HashMap<i64, Attach>> {
    map.lock().unwrap_or_else(|e| e.into_inner())
}

// ===== audio engine (feature `audio`) ======================================

/// cpal streams live on a dedicated thread (cpal::Stream is !Send, so it
/// must not leak into VoiceInner / async tasks). Dropping or signaling
/// `stop` ends the thread, which drops the streams.
#[cfg(feature = "audio")]
struct AudioEngine {
    stop: std::sync::mpsc::Sender<()>,
    _thread: std::thread::JoinHandle<()>,
}

/// Frame length in samples for the configured frame duration.
#[cfg(feature = "audio")]
fn frame_samples(cfg: &VoiceCfg) -> usize {
    let ms = cfg.audio_frame_ms.clamp(10, 60);
    (8000usize * ms as usize) / 1000
}

/// Start the audio thread (8 kHz mono S16LE, default devices). Idempotent
/// while any attach is live. Failure ⇒ attach gets audio_unavailable.
#[cfg(feature = "audio")]
fn start_engine(inner: &VoiceInner) -> anyhow::Result<()> {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

    let mut guard = inner.audio.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return Ok(());
    }
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let (init_tx, init_rx) = std::sync::mpsc::channel::<anyhow::Result<()>>();
    let attaches = inner.attaches.clone();
    let frame = frame_samples(&inner.cfg);
    let device = inner.cfg.audio_device.clone();

    let thread = std::thread::Builder::new()
        .name("voice-audio".into())
        .spawn(move || {
            let result = (|| -> anyhow::Result<()> {
                let host = cpal::default_host();
                // "default" → host defaults; otherwise the exact ALSA name
                // of the USB adapter, selected for both directions (duplex).
                let (in_dev, out_dev) = if device == "default" {
                    let i = host
                        .default_input_device()
                        .ok_or_else(|| anyhow::anyhow!("no default input device"))?;
                    let o = host
                        .default_output_device()
                        .ok_or_else(|| anyhow::anyhow!("no default output device"))?;
                    (i, o)
                } else {
                    let matches_name = |d: &cpal::Device| d.name().as_deref().ok() == Some(device.as_str());
                    let i = host
                        .input_devices()?
                        .find(matches_name)
                        .ok_or_else(|| anyhow::anyhow!("audio input device not found: {device}"))?;
                    let o = host
                        .output_devices()?
                        .find(matches_name)
                        .ok_or_else(|| anyhow::anyhow!("audio output device not found: {device}"))?;
                    (i, o)
                };
                let scfg = cpal::StreamConfig {
                    channels: 1,
                    sample_rate: cpal::SampleRate(8000),
                    buffer_size: cpal::BufferSize::Default,
                };
                let mic_acc: Arc<StdMutex<Vec<i16>>> = Arc::new(StdMutex::new(Vec::new()));
                let a_in = attaches.clone();
                let in_stream = in_dev.build_input_stream(
                    &scfg,
                    move |data: &[i16], _| {
                        let mut acc = mic_acc.lock().unwrap_or_else(|e| e.into_inner());
                        acc.extend_from_slice(data);
                        while acc.len() >= frame {
                            let chunk: Vec<i16> = acc.drain(..frame).collect();
                            let bytes = encode_frame(&chunk);
                            let map = lock_map(&a_in);
                            for a in map.values() {
                                // bounded: drop rather than queue unbounded
                                let _ = a.sink.try_send(axum::extract::ws::Message::Binary(bytes.clone().into()));
                            }
                        }
                    },
                    |err| tracing::warn!(error = %err, "audio input error"),
                    None,
                )?;
                let a_out = attaches.clone();
                let out_stream = out_dev.build_output_stream(
                    &scfg,
                    move |data: &mut [i16], _| {
                        for s in data.iter_mut() {
                            *s = 0;
                        }
                        let map = lock_map(&a_out);
                        for a in map.values() {
                            let mut q = a.spk.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(frame_data) = q.pop_front() {
                                for (i, s) in frame_data.iter().enumerate() {
                                    if let Some(slot) = data.get_mut(i) {
                                        *slot = slot.saturating_add(*s);
                                    }
                                }
                            }
                        }
                    },
                    |err| tracing::warn!(error = %err, "audio output error"),
                    None,
                )?;
                in_stream.play()?;
                out_stream.play()?;
                Ok(())
            })();
            let ok = result.is_ok();
            let _ = init_tx.send(result);
            if ok {
                let _ = stop_rx.recv(); // park until stop/drop
                // streams dropped here
            }
        })
        .map_err(|e| anyhow::anyhow!("audio thread spawn: {e}"))?;

    // propagate stream-build failures to the caller
    match init_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => {
            *guard = Some(AudioEngine { stop: stop_tx, _thread: thread });
            Ok(())
        }
        Ok(Err(e)) => {
            let _ = thread.join();
            Err(e)
        }
        Err(_) => {
            let _ = stop_tx.send(());
            let _ = thread.join();
            Err(anyhow::anyhow!("audio init timeout"))
        }
    }
}

/// No-audio builds: audio attach is structurally unavailable (the close
/// code and message match the runtime engine-failure path).
#[cfg(not(feature = "audio"))]
fn start_engine(_inner: &VoiceInner) -> anyhow::Result<()> {
    Err(anyhow::anyhow!("compiled without the `audio` feature"))
}

/// Stop the audio thread when the last attach is gone.
#[cfg(feature = "audio")]
fn maybe_stop_engine(inner: &VoiceInner) {
    if lock_map(&inner.attaches).is_empty() {
        let mut g = inner.audio.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(engine) = g.take() {
            let _ = engine.stop.send(());
        }
    }
}

/// After an active audio call loses its socket: wait the grace window,
/// then end the call with audio_lost unless a client reattached.
fn spawn_audio_grace(inner: Arc<VoiceInner>, call_id: i64) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(inner.cfg.audio_grace_s.max(1))).await;
        if lock_map(&inner.attaches).contains_key(&call_id) {
            return; // reattached inside the window
        }
        if let Ok(Some(row)) = inner.db.get_call(call_id).await {
            if row.status == CallStatus::Active && row.audio {
                let _ = inner.modem.at("AT+CHUP", Duration::from_secs(5)).await;
                if let Ok(Some(ended)) = inner
                    .db
                    .transition_call(call_id, CallStatus::Active, CallStatus::Ended, Some("audio_lost"))
                    .await
                {
                    publish_call(&inner, &ended, false).await;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g711u_anchors() {
        // µ-law silence and -0 anchors
        assert_eq!(g711u_encode(0), 0xFF);
        assert_eq!(g711u_encode(-1), 0x7F);
        assert_eq!(g711u_decode(0xFF), 0);
        // positive extreme clamps to segment 7 top
        assert_eq!(g711u_encode(32767), 0x80);
        assert_eq!(g711u_decode(0x80), 32124);
        assert_eq!(g711u_decode(g711u_encode(-32767)), -32124);
    }

    #[test]
    fn g711u_roundtrip_tolerance() {
        for i in 0..=4096i32 {
            for scale in [1i32, 8, 64] {
                let s = (i * scale - 4096 * scale) as i16;
                let d = g711u_decode(g711u_encode(s));
                let err = (i32::from(d) - i32::from(s)).abs();
                let tol = 8 + (i32::from(s).unsigned_abs() as i32 / 32);
                assert!(err <= tol, "{s} → {d} (err {err} > {tol})");
            }
        }
    }

    #[test]
    fn frame_roundtrip_lengths() {
        let samples: Vec<i16> = (0..160).map(|i| (i as i16 - 80) * 40).collect();
        let bytes = encode_frame(&samples);
        assert_eq!(bytes.len(), 160);
        let back = decode_frame(&bytes);
        assert_eq!(back.len(), 160);
    }

    #[test]
    fn digit_validation() {
        assert!(valid_digits("123#"));
        assert!(valid_digits("0123456789ABCD*#"));
        assert!(valid_digits("abcd"));
        assert!(!valid_digits(""));
        assert!(!valid_digits("1e2"));
        assert!(!valid_digits("12;34"));
        assert!(!valid_digits("1 2"));
    }

    #[test]
    fn cend_cause_mapping() {
        assert_eq!(map_cend_cause(Some("17"), true), "busy");
        assert_eq!(map_cend_cause(None, true), "no_answer");
        assert_eq!(map_cend_cause(Some("16"), true), "no_answer");
        assert_eq!(map_cend_cause(None, false), "remote_hangup");
        assert_eq!(map_cend_cause(Some("17"), false), "busy");
        assert_eq!(map_cend_cause(Some("31"), false), "remote_hangup_31");
    }
}


