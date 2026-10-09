//! Serial AT engine (spec §5): single command queue, URC pump, boot init,
//! CMGL import, SMS submit pipeline with per-segment transient retry, CDS
//! rollup, status polling, and the 4-rung recovery ladder. Only this
//! module touches the serial port. Only this module drives GPIO.
//!
//! Architecture: one blocking std thread owns the serial port and executes
//! every request (plain AT or the multi-phase CMGS prompt→PDU→+CMGS flow)
//! atomically, to completion, in arrival order — that IS the serialized
//! queue. An async worker owns the thread's lifecycle, boots the modem,
//! drains `take_sendable_outbox`, reacts to CMTI/CDS URCs (via its own
//! subscription to the URC broadcast), polls status into a `watch`, and
//! drives the recovery ladder. Voice/WAP-push URCs are broadcast for
//! voice.rs/mms.rs; Cmti/Cds never escape this module.
//!
//! SECURITY (spec §7): no unwrap on parsed URC/modem bytes; PDU hex goes
//! through pdu::decode_pdu (total function); response lines are capped
//! (512 lines × 4096 bytes) before anyone sees them; tracing never logs
//! message text — URC kinds and capped metadata only. No unsafe here.

use crate::config::ModemProfile;
use crate::db::{Db, StageResult};
use crate::envelope::{inbox_item_json, EventBus};
use crate::pdu::{self, CdsStatus, PduKind};
use crate::types::{
    Event, ModemInfo, ModemSnapshot, ModemState, NetworkInfo, SimInfo, TransportStatus,
};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot, watch, Mutex, Notify};

const PROMPT_TIMEOUT: Duration = Duration::from_secs(5);
const CMGS_TOTAL_TIMEOUT: Duration = Duration::from_secs(90);
const CMD_TIMEOUT: Duration = Duration::from_secs(10);
const LINE_CAP_BYTES: usize = 4096;
const LINES_CAP: usize = 512;
const PDU_HEX_CAP: usize = 1000;
#[derive(Debug, Clone)]
pub struct ModemConfig {
    pub serial_path: String,
    pub profile: ModemProfile,
    pub queue_limit: usize,
    pub submit_retries: u32,
    pub retry_interval_s: u64,
    pub csmp_vp: u8,
    pub max_segments: u8,
    pub gpio_power_cycle: bool,
    pub pwrkey_gpio: u32,
    pub recovery_backoff_s: u64,
    pub mms_enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AtError {
    Timeout,
    Cms(u16),
    Cme(u16),
    Unresponsive,
}

impl std::fmt::Display for AtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AtError::Timeout => write!(f, "at_timeout"),
            AtError::Cms(c) => write!(f, "cms_error_{c}"),
            AtError::Cme(c) => write!(f, "cme_error_{c}"),
            AtError::Unresponsive => write!(f, "modem_unresponsive"),
        }
    }
}

/// URC pump output. Voice events (Ring/Clip/Begin/End/NoCarrier/Dtmf) feed
/// voice.rs; WapPush feeds mms.rs; Cmti/Cds are handled internally.
#[derive(Debug, Clone)]
pub enum Urc {
    Cmti { index: u32 },
    Cds { pdu_hex: String },
    Ring,
    Clip { number: String },
    VoiceCallBegin,
    VoiceCallEnd,
    NoCarrier { cause: Option<String> },
    Dtmf { digits: String },
    WapPush { deliver: crate::pdu::DeliverPdu },
    Other(String),
}

// ===== request protocol (async side → port thread) ========================

enum Request {
    At {
        cmd: String,
        timeout: Duration,
        resp: oneshot::Sender<Result<Vec<String>, AtError>>,
    },
    /// Full CMGS flow: prompt → PDU+Ctrl-Z → `+CMGS: <mr>` → OK.
    Cmgs {
        tp_octets: usize,
        hex: String,
        resp: oneshot::Sender<Result<u16, CmgsFail>>,
    },
    /// Drop the port and retry-open until it returns (post-CFUN/PWRKEY
    /// re-enumeration). `wait` bounds the retry window.
    Reopen {
        wait: Duration,
        resp: oneshot::Sender<Result<(), AtError>>,
    },
    Shutdown,
}

/// CMGS-specific failure so the send pipeline can distinguish "no `>`
/// prompt (abort attempt, retryable)" from "prompt seen but +CMGS never
/// answered (→ failed/submit_timeout)".
enum CmgsFail {
    At(AtError),
    NoPrompt,
}

struct ModemInner {
    tx: mpsc::Sender<Request>,
    urc: broadcast::Sender<Urc>,
    snap: watch::Receiver<ModemSnapshot>,
    shutdown: Arc<AtomicBool>,
    stop: Arc<Notify>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl ModemInner {
    async fn at(&self, cmd: &str, timeout: Duration) -> Result<Vec<String>, AtError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Request::At { cmd: cmd.to_string(), timeout, resp: tx })
            .map_err(|_| AtError::Unresponsive)?;
        match tokio::time::timeout(timeout + Duration::from_secs(2), rx).await {
            Ok(Ok(r)) => r,
            _ => Err(AtError::Unresponsive),
        }
    }

    async fn cmgs(&self, tp_octets: usize, hex: &str) -> Result<u16, CmgsFail> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Request::Cmgs { tp_octets, hex: hex.to_string(), resp: tx })
            .map_err(|_| CmgsFail::At(AtError::Unresponsive))?;
        let budget = CMGS_TOTAL_TIMEOUT + PROMPT_TIMEOUT + Duration::from_secs(2);
        match tokio::time::timeout(budget, rx).await {
            Ok(Ok(r)) => r,
            _ => Err(CmgsFail::At(AtError::Unresponsive)),
        }
    }
}

#[derive(Clone)]
pub struct Modem {
    /// Implementation detail — internal channels. Do not expose raw
    /// internals; this handle is shared across api/voice/mms.
    inner: Arc<ModemInner>,
}

impl Modem {
    /// Open the port, run boot init + CMGL import, spawn the worker task.
    /// Fails fast with a clear error if the serial path can't be opened.
    pub fn spawn(cfg: ModemConfig, db: Db, events: EventBus) -> anyhow::Result<Modem> {
        let port = open_port(&cfg.serial_path)?;
        let (tx, rx) = mpsc::channel::<Request>();
        let (urc_tx, _) = broadcast::channel::<Urc>(256);
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(Notify::new());
        let (snap_tx, snap_rx) = watch::channel(ModemSnapshot {
            modem: ModemInfo {
                model: String::new(),
                fw: String::new(),
                state: Some(ModemState::Probing),
            },
            sim: SimInfo::default(),
            network: NetworkInfo::default(),
        });

        let thread = {
            let shutdown = shutdown.clone();
            let path = cfg.serial_path.clone();
            let urc_thread = urc_tx.clone();
            std::thread::Builder::new()
                .name("modem-port".into())
                .spawn(move || port_thread(path, port, rx, urc_thread, shutdown))?
        };

        let inner = Arc::new(ModemInner {
            tx,
            urc: urc_tx.clone(),
            snap: snap_rx,
            shutdown,
            stop,
            worker: Mutex::new(None),
            thread: Mutex::new(Some(thread)),
        });

        let worker = tokio::spawn(worker_loop(cfg, db, events, urc_tx, snap_tx, inner.clone()));
        if let Ok(mut g) = inner.worker.try_lock() {
            *g = Some(worker);
        }

        Ok(Modem { inner })
    }

    /// Queue-serialized raw AT command for voice/bring-up use. Returns the
    /// collected response lines (without the final OK).
    pub async fn at(&self, cmd: impl AsRef<str>, timeout: Duration) -> Result<Vec<String>, AtError> {
        self.inner.at(cmd.as_ref(), timeout).await
    }

    /// Live modem-side snapshot (watch-backed, always cheap).
    pub async fn snapshot(&self) -> ModemSnapshot {
        self.inner.snap.borrow().clone()
    }

    pub fn urc_subscribe(&self) -> broadcast::Receiver<Urc> {
        self.inner.urc.subscribe()
    }

    pub async fn stop(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.stop.notify_one();
        let _ = self.inner.tx.send(Request::Shutdown);
        let worker = self.inner.worker.lock().await.take();
        if let Some(h) = worker {
            let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
        }
        // Port thread is detached: it observes the shutdown flag within one
        // read budget (or one in-flight command deadline) and exits.
        let _ = self.inner.thread.lock().await.take();
    }
}

fn open_port(path: &str) -> anyhow::Result<Box<dyn serialport::SerialPort>> {
    let port = serialport::new(path, 115_200)
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .flow_control(serialport::FlowControl::None)
        .timeout(Duration::from_millis(50))
        .open()
        .map_err(|e| anyhow::anyhow!("open {path}: {e}"))?;
    Ok(port)
}

// ===== port thread =========================================================

/// Splits \r/\n-terminated lines out of the raw byte stream, capping each
/// line at LINE_CAP_BYTES (an over-long line is dropped and resynced on
/// the next terminator). Also remembers a pending `+CDS:`/`+CMT:` header
/// whose raw PDU hex follows on the next line.
#[derive(Default)]
struct LineFeed {
    buf: Vec<u8>,
    pending_pdu_hex: bool,
}

impl LineFeed {
    fn feed(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        for &b in bytes {
            if b == b'\r' || b == b'\n' {
                if !self.buf.is_empty() {
                    if self.buf.len() <= LINE_CAP_BYTES {
                        if let Ok(s) = String::from_utf8(std::mem::take(&mut self.buf)) {
                            out.push(s);
                        }
                    } else {
                        self.buf.clear();
                    }
                }
            } else if self.buf.len() < LINE_CAP_BYTES {
                self.buf.push(b);
            }
            // bytes past the cap inside one line are dropped
        }
        out
    }
}

/// One in-flight request on the port thread.
struct Pending {
    deadline: Instant,
    lines: Vec<String>,
    kind: PendingKind,
}

enum PendingKind {
    At(oneshot::Sender<Result<Vec<String>, AtError>>),
    /// phase 0 = awaiting `>` prompt, 1 = PDU written, awaiting +CMGS/OK.
    Cmgs {
        phase: u8,
        pdu_hex: String,
        mr: Option<u16>,
        resp: oneshot::Sender<Result<u16, CmgsFail>>,
    },
}

impl Pending {
    fn cmgs_phase(&self) -> Option<u8> {
        match &self.kind {
            PendingKind::Cmgs { phase, .. } => Some(*phase),
            PendingKind::At(_) => None,
        }
    }
    /// Consume and answer the request with `Ok`.
    fn complete_ok(self) {
        match self.kind {
            PendingKind::At(resp) => {
                let _ = resp.send(Ok(self.lines));
            }
            PendingKind::Cmgs { mr, resp, .. } => {
                // OK without a +CMGS line: treat as submit timeout.
                let _ = resp.send(mr.map(Ok).unwrap_or(Err(CmgsFail::At(AtError::Timeout))));
            }
        }
    }
    fn complete_err(self, err: AtError) {
        match self.kind {
            PendingKind::At(resp) => {
                let _ = resp.send(Err(err));
            }
            PendingKind::Cmgs { resp, .. } => {
                let _ = resp.send(Err(CmgsFail::At(err)));
            }
        }
    }
    fn complete_no_prompt(self) {
        match self.kind {
            PendingKind::Cmgs { resp, .. } => {
                let _ = resp.send(Err(CmgsFail::NoPrompt));
            }
            PendingKind::At(resp) => {
                let _ = resp.send(Err(AtError::Timeout));
            }
        }
    }
}

/// Command final / URC / data classification. Total: every byte-string
/// maps somewhere; unknown shapes degrade to `Data`/`Other`, never panic.
enum Line {
    Ok,
    PlainError,
    Cme(u16),
    Cms(u16),
    CmgsMr(u16),
    /// `+CDS: <n>` / `+CMT: <n>` header — next line is raw PDU hex.
    PduHeader,
    Urc(Urc),
    Data,
}

fn trailing_code(line: &str) -> Option<u16> {
    let tail = line.rsplit(':').next().unwrap_or("").trim();
    let digits: String = tail.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || digits.len() > 5 {
        return None;
    }
    digits.parse::<u16>().ok()
}

fn classify(line: &str) -> Line {
    let t = line.trim();
    if t == "OK" {
        return Line::Ok;
    }
    if t == "ERROR" {
        return Line::PlainError;
    }
    if t.starts_with("+CME ERROR:") {
        return Line::Cme(trailing_code(t).unwrap_or(0));
    }
    if t.starts_with("+CMS ERROR:") {
        return Line::Cms(trailing_code(t).unwrap_or(500));
    }
    if t.starts_with("+CMGS:") {
        return match trailing_code(t) {
            Some(mr) => Line::CmgsMr(mr),
            None => Line::Data,
        };
    }
    // +CDS/+CMT URCs are two-line: header (length only) then raw hex.
    if t.starts_with("+CDS:") || t.starts_with("+CMT:") {
        return Line::PduHeader;
    }
    if t == "RING" || t == "+RING" {
        return Line::Urc(Urc::Ring);
    }
    if t.starts_with("+CLIP:") {
        let first = t[6..].split(',').next().unwrap_or("").trim();
        let num = first.trim_matches('"').trim();
        let num = num.strip_prefix('+').unwrap_or(num);
        return Line::Urc(Urc::Clip { number: num.to_string() });
    }
    if t == "NO CARRIER" {
        return Line::Urc(Urc::NoCarrier { cause: None });
    }
    if t.starts_with("^CEND") {
        return Line::Urc(Urc::VoiceCallEnd);
    }
    if t.starts_with("+DTMF:") {
        let d = t[6..].trim_matches('"').trim();
        return Line::Urc(Urc::Dtmf { digits: d.chars().take(16).collect() });
    }
    if t.starts_with("+CMTI:") || t.starts_with("+CDSI:") {
        // +CDSI: a status report landed in storage — the CMGR/CMGD flow
        // serves both shapes (handle_pdu routes deliver vs status report).
        let idx = t.rsplit(',').next().unwrap_or("").trim();
        if let Ok(i) = idx.parse::<u32>() {
            return Line::Urc(Urc::Cmti { index: i });
        }
        return Line::Data;
    }
    // SIMCom voice lifecycle URCs (plain, no '+')
    if t == "VOICE CALL: BEGIN" {
        return Line::Urc(Urc::VoiceCallBegin);
    }
    if t == "VOICE CALL: END" || t.starts_with("VOICE CALL: END:") {
        return Line::Urc(Urc::VoiceCallEnd);
    }
    if t.starts_with("+CEND:") {
        // +CEND: <n>,<cause> — cause after the last comma, capped
        let cause = t.rsplit(',').next().unwrap_or("").trim();
        let cause: String = cause.chars().take(8).filter(|c| c.is_ascii_digit()).collect();
        return Line::Urc(Urc::NoCarrier { cause: (!cause.is_empty()).then_some(cause) });
    }
    // Everything else starting with '+' is ambiguous between a command
    // response (+CSQ:, +CPIN:, +QCFG: ...) and an unknown URC; the router
    // decides by context (pending command ⇒ response data).
    Line::Data
}

/// Even-length, non-empty, all-ASCII-hex, capped — the test for "this
/// line is a raw PDU payload".
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.len() <= PDU_HEX_CAP && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Route one completed line: command finals resolve the pending request;
/// URCs broadcast; data lines accumulate on the pending command.
fn handle_line(
    line: String,
    pending: &mut Option<Pending>,
    feed: &mut LineFeed,
    urc_tx: &broadcast::Sender<Urc>,
) {
    // two-line +CDS/+CMT capture: the header flagged the next line as hex
    if feed.pending_pdu_hex {
        feed.pending_pdu_hex = false;
        if is_hex(line.trim()) {
            let hex = line.trim().to_ascii_uppercase();
            tracing::debug!(octets = hex.len() / 2, "pdu urc received");
            let _ = urc_tx.send(Urc::Cds { pdu_hex: hex });
            return;
        }
        // not hex after all — fall through to normal classification
    }
    match classify(&line) {
        Line::Ok => {
            if let Some(p) = pending.take() {
                p.complete_ok();
            }
        }
        Line::PlainError => {
            if let Some(p) = pending.take() {
                p.complete_err(AtError::Cme(0));
            }
        }
        Line::Cme(c) => {
            if let Some(p) = pending.take() {
                p.complete_err(AtError::Cme(c));
            }
        }
        Line::Cms(c) => {
            if let Some(p) = pending.take() {
                p.complete_err(AtError::Cms(c));
            }
        }
        Line::CmgsMr(mr) => {
            if let Some(PendingKind::Cmgs { mr: slot, .. }) = pending.as_mut().map(|p| &mut p.kind) {
                *slot = Some(mr);
            }
        }
        Line::PduHeader => {
            feed.pending_pdu_hex = true;
        }
        Line::Urc(u) => {
            let _ = urc_tx.send(u);
        }
        Line::Data => match pending.as_mut() {
            Some(p) if p.lines.len() < LINES_CAP => p.lines.push(line),
            // idle '+'-shaped noise is still a URC worth forwarding
            _ if line.trim_start().starts_with('+') => {
                let _ = urc_tx.send(Urc::Other(line.chars().take(200).collect()));
            }
            _ => {}
        },
    }
}

fn write_bytes(port: &mut Option<Box<dyn serialport::SerialPort>>, bytes: &[u8]) -> bool {
    match port {
        Some(p) => p.write_all(bytes).is_ok() && p.flush().is_ok(),
        None => false,
    }
}

fn write_cmd(port: &mut Option<Box<dyn serialport::SerialPort>>, cmd: &str) -> bool {
    let mut v = Vec::with_capacity(cmd.len() + 1);
    v.extend_from_slice(cmd.as_bytes());
    v.push(b'\r');
    write_bytes(port, &v)
}

/// Drop the port and keep retrying `open_port` until it returns or the
/// window closes. Leaves `None` on total failure (thread keeps polling;
/// requests fail Unresponsive until something reopens it).
fn reopen(
    path: &str,
    slot: &mut Option<Box<dyn serialport::SerialPort>>,
    wait: Duration,
    shutdown: &AtomicBool,
) {
    *slot = None;
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline && !shutdown.load(Ordering::SeqCst) {
        if let Ok(p) = open_port(path) {
            *slot = Some(p);
            return;
        }
        std::thread::sleep(Duration::from_millis(2000));
    }
}

#[allow(clippy::too_many_arguments)]
fn port_thread(
    path: String,
    port: Box<dyn serialport::SerialPort>,
    rx: mpsc::Receiver<Request>,
    urc_tx: broadcast::Sender<Urc>,
    shutdown: Arc<AtomicBool>,
) {
    let mut port: Option<Box<dyn serialport::SerialPort>> = Some(port);
    let mut feed = LineFeed::default();
    let mut pending: Option<Pending> = None;
    let mut buf = [0u8; 512];

    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }

        // 1. pick up one request when idle
        if pending.is_none() {
            match rx.recv_timeout(Duration::from_millis(20)) {
                Ok(Request::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Ok(Request::At { cmd, timeout, resp }) => {
                    if write_cmd(&mut port, &cmd) {
                        pending = Some(Pending {
                            deadline: Instant::now() + timeout,
                            lines: Vec::new(),
                            kind: PendingKind::At(resp),
                        });
                    } else {
                        let _ = resp.send(Err(AtError::Unresponsive));
                    }
                }
                Ok(Request::Cmgs { tp_octets, hex, resp }) => {
                    let cmd = format!("AT+CMGS={tp_octets}");
                    if write_cmd(&mut port, &cmd) {
                        pending = Some(Pending {
                            deadline: Instant::now() + PROMPT_TIMEOUT,
                            lines: Vec::new(),
                            kind: PendingKind::Cmgs { phase: 0, pdu_hex: hex, mr: None, resp },
                        });
                    } else {
                        let _ = resp.send(Err(CmgsFail::At(AtError::Unresponsive)));
                    }
                }
                Ok(Request::Reopen { wait, resp }) => {
                    reopen(&path, &mut port, wait, &shutdown);
                    // stale pre-reboot fragments must not misparse
                    feed.buf.clear();
                    feed.pending_pdu_hex = false;
                    let r = if port.is_some() { Ok(()) } else { Err(AtError::Unresponsive) };
                    let _ = resp.send(r);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }

        // 2. read the wire with the right budget
        let read_to = match &pending {
            Some(p) => p
                .deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50))
                .max(Duration::from_millis(1)),
            None => Duration::from_millis(20),
        };
        let n = match port.as_mut() {
            Some(p) => {
                let _ = p.set_timeout(read_to);
                match p.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => 0,
                    Err(_) => 0, // device gone: silence; Reopen/ladder heals
                }
            }
            None => {
                std::thread::sleep(Duration::from_millis(500));
                0
            }
        };

        if n > 0 {
            let bytes = &buf[..n];
            // CMGS phase 0: the `>` prompt is a raw byte, never a line
            if pending.as_ref().and_then(|p| p.cmgs_phase()) == Some(0) && bytes.contains(&b'>') {
                let hex = match pending.as_mut().map(|p| &mut p.kind) {
                    Some(PendingKind::Cmgs { pdu_hex, .. }) => std::mem::take(pdu_hex),
                    _ => String::new(),
                };
                let mut payload = hex.into_bytes();
                payload.push(0x1a); // Ctrl-Z
                if !write_bytes(&mut port, &payload) {
                    if let Some(p) = pending.take() {
                        p.complete_err(AtError::Unresponsive);
                    }
                } else if let Some(p) = pending.as_mut() {
                    p.deadline = Instant::now() + CMGS_TOTAL_TIMEOUT;
                    if let PendingKind::Cmgs { phase, .. } = &mut p.kind {
                        *phase = 1;
                    }
                }
                // bytes forming the prompt frame are not command data
            } else {
                for line in feed.feed(bytes) {
                    handle_line(line, &mut pending, &mut feed, &urc_tx);
                }
            }
        }

        // 3. enforce deadlines
        let expired = pending
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.deadline);
        if expired {
            let prompt_phase = pending.as_ref().and_then(|p| p.cmgs_phase()) == Some(0);
            if prompt_phase {
                let _ = write_bytes(&mut port, b"\x1b"); // raw ESC abort
                if let Some(p) = pending.take() {
                    p.complete_no_prompt();
                }
            } else if let Some(p) = pending.take() {
                p.complete_err(AtError::Timeout);
            }
        }
    }
}

// ===== async worker ========================================================

struct Worker {
    cfg: ModemConfig,
    db: Db,
    events: EventBus,
    urc_tx: broadcast::Sender<Urc>,
    snap_tx: watch::Sender<ModemSnapshot>,
    inner: Arc<ModemInner>,
    state: ModemState,
    info: ModemInfo,
    sim: SimInfo,
    net: NetworkInfo,
    /// consecutive Timeout/Unresponsive at() results
    fail_streak: u32,
    busy_sending: bool,
}

async fn worker_loop(
    cfg: ModemConfig,
    db: Db,
    events: EventBus,
    urc_tx: broadcast::Sender<Urc>,
    snap_tx: watch::Sender<ModemSnapshot>,
    inner: Arc<ModemInner>,
) {
    let mut w = Worker {
        cfg,
        db,
        events,
        urc_tx: urc_tx.clone(),
        snap_tx,
        inner,
        state: ModemState::Probing,
        info: ModemInfo { model: String::new(), fw: String::new(), state: None },
        sim: SimInfo::default(),
        net: NetworkInfo::default(),
        fail_streak: 0,
        busy_sending: false,
    };
    let mut urc_rx = w.urc_tx.subscribe();
    let mut send_tick = tokio::time::interval(Duration::from_secs(1));
    let mut poll_tick = tokio::time::interval(Duration::from_secs(10));
    send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let _ = send_tick.tick().await; // first tick fires immediately
    let _ = poll_tick.tick().await;

    w.boot().await;

    loop {
        tokio::select! {
            _ = w.inner.stop.notified() => break,
            ev = urc_rx.recv() => match ev {
                Ok(Urc::Cmti { index }) => w.handle_cmti(index).await,
                Ok(Urc::Cds { pdu_hex }) => w.handle_pdu(&pdu_hex).await,
                Ok(Urc::Other(line)) => {
                    tracing::debug!(target: "cellmatik::modem", urc = %line, "unhandled URC");
                }
                Ok(_) => {} // voice/WAP-push URCs are consumed by their subscribers
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "urc lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            _ = send_tick.tick() => w.send_cycle().await,
            _ = poll_tick.tick() => {
                w.status_poll().await;
            },
        }
    }
}

impl Worker {
    fn publish_snap(&self) {
        let _ = self.snap_tx.send(ModemSnapshot {
            modem: ModemInfo { state: Some(self.state.clone()), ..self.info.clone() },
            sim: self.sim.clone(),
            network: self.net.clone(),
        });
    }

    /// at() with liveness accounting: only timeouts/unresponsiveness bump
    /// the recovery streak; CME/CMS mean the modem is alive and unhappy.
    async fn wat(&mut self, cmd: &str, timeout: Duration) -> Result<Vec<String>, AtError> {
        let r = self.inner.at(cmd, timeout).await;
        match &r {
            Err(AtError::Timeout) | Err(AtError::Unresponsive) => self.fail_streak += 1,
            Ok(_) => self.fail_streak = 0,
            _ => {}
        }
        r
    }

    /// Boot: init ladder → (optional) ECM flip + reboot + re-init → CMGL
    /// import. If the modem is silent, run the recovery ladder to ready.
    async fn boot(&mut self) {
        if !self.run_init().await {
            if !self.ensure_ready().await {
                return; // ladder parks in unresponsive; ticks keep retrying
            }
        }
        self.maybe_ecm_flip().await;
        self.cmgl_import().await;
        self.status_poll().await;
    }

    /// Init ladder (spec §5). Tolerant of CME/CMS (unsupported command ≠
    /// dead modem); any timeout aborts with false.
    async fn run_init(&mut self) -> bool {
        let profile_cmds: &[&str] = match self.cfg.profile {
            ModemProfile::Sim7600 => &["AT+DDET=1", "AT+CPCMBANDWIDTH=1,1"],
            ModemProfile::Rm520n => &[],
        };
        let ladder: Vec<&str> = [
            "ATE0",
            "AT+CMEE=2",
            "AT+CMGF=0",
            "AT+CSCS=\"GSM\"",
            "AT+CNMI=2,1,0,2,0",
            "AT+CPMS=\"ME\",\"ME\",\"ME\"",
        ]
        .iter()
        .chain(profile_cmds.iter())
        .copied()
        .collect();
        for cmd in ladder {
            let name = cmd.split('=').next().unwrap_or(cmd);
            match self.wat(cmd, CMD_TIMEOUT).await {
                Ok(_) => tracing::debug!(name, "init ok"),
                Err(AtError::Cme(c)) | Err(AtError::Cms(c)) => {
                    tracing::warn!(cmd, code = c, "init cmd rejected (continuing)");
                }
                Err(e) => {
                    tracing::warn!(cmd, error = %e, "init cmd failed");
                    return false;
                }
            }
        }
        // The ladder tolerates rejects; read back the effective CNMI so a
        // silently-rejected routing change is visible. <ds>=2 routes CDS
        // as +CDS; anything else means status reports land in storage
        // (+CDSI / CMGL import path instead).
        if let Ok(lines) = self.wat("AT+CNMI?", CMD_TIMEOUT).await {
            if let Some(l) = lines.iter().find(|l| l.starts_with("+CNMI:")) {
                let ds = l
                    .split(':')
                    .nth(1)
                    .and_then(|r| r.split(',').nth(3))
                    .and_then(|s| s.trim().parse::<i64>().ok());
                match ds {
                    Some(2) => tracing::debug!(cnmi = %l.trim(), "cnmi effective, cds routed to TE"),
                    Some(other) => tracing::warn!(
                        ds = other,
                        "cnmi does not route +CDS to TE; status reports will arrive via storage"
                    ),
                    None => tracing::debug!(cnmi = %l.trim(), "cnmi readback unparseable"),
                }
            }
        }
        true
    }

    /// Two-mode rule: when MMS is enabled the modem must be in ECM mode
    /// (rm520n: AT+QCFG="usbnet",1). Query first — only reboot when the
    /// value actually differs, so restarts don't pay 30-60 s every boot.
    /// Sim7600 ECM is provisioned at modem swap (its firmware has no
    /// runtime switch we can rely on); nothing to do here.
    async fn maybe_ecm_flip(&mut self) {
        if !self.cfg.mms_enabled || self.cfg.profile != ModemProfile::Rm520n {
            return;
        }
        let current = match self.wat("AT+QCFG=\"usbnet\"", CMD_TIMEOUT).await {
            Ok(lines) => lines
                .iter()
                .find_map(|l| {
                    let t = l.trim();
                    t.strip_prefix("+QCFG: \"usbnet\",")?
                        .trim()
                        .split(',')
                        .next()?
                        .trim()
                        .parse::<u32>()
                        .ok()
                })
                .unwrap_or(u32::MAX),
            Err(_) => return,
        };
        if current == 1 {
            tracing::debug!("usbnet already ECM");
            return;
        }
        match self.wat("AT+QCFG=\"usbnet\",1", CMD_TIMEOUT).await {
            Ok(_) => {
                tracing::info!("usbnet → ECM; rebooting modem");
                let _ = self.wat("AT+CFUN=1,1", Duration::from_secs(5)).await;
                if self.reopen_port(Duration::from_secs(60)).await {
                    self.run_init().await;
                    self.cmgl_import().await;
                }
            }
            Err(e) => tracing::warn!(error = %e, "usbnet flip rejected (continuing without)"),
        }
    }

    async fn reopen_port(&mut self, wait: Duration) -> bool {
        let (tx, rx) = oneshot::channel();
        if self
            .inner
            .tx
            .send(Request::Reopen { wait, resp: tx })
            .is_err()
        {
            return false;
        }
        matches!(
            tokio::time::timeout(wait + Duration::from_secs(2), rx).await,
            Ok(Ok(Ok(())))
        )
    }

    /// AT+CMGL=4 import through the same decoder as live URCs, then
    /// delete everything imported.
    async fn cmgl_import(&mut self) {
        let lines = match self.wat("AT+CMGL=4", Duration::from_secs(30)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "cmgl import failed");
                return;
            }
        };
        let mut indices: Vec<u32> = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            if lines[i].starts_with("+CMGL:") && i + 1 < lines.len() && is_hex(lines[i + 1].trim()) {
                // +CMGL: <index>,<stat>,[<alpha>],<length> — index is the
                // FIRST integer; the last one is the length (a wrong delete
                // target leaves the row stored forever).
                let idx = lines[i]
                    .strip_prefix("+CMGL:")
                    .and_then(|r| r.split(',').next())
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(0);
                self.handle_pdu(lines[i + 1].trim()).await;
                indices.push(idx);
                i += 2;
                continue;
            }
            i += 1;
        }
        for idx in indices {
            if idx > 0 {
                let _ = self.wat(&format!("AT+CMGD={idx}"), Duration::from_secs(5)).await;
            }
        }
    }

    /// Route one decoded-or-raw PDU (CMTI/CDS URC, CMGR read, CMGL row).
    async fn handle_pdu(&mut self, hex: &str) {
        match pdu::decode_pdu(hex) {
            Ok(PduKind::Deliver(d)) => self.deliver(d).await,
            Ok(PduKind::StatusReport(sr)) => self.status_report(sr.mr, sr.status).await,
            Ok(PduKind::Other) | Err(_) => {
                tracing::warn!(octets = hex.len() / 2, "undecodable inbound pdu dropped");
                tracing::debug!(hex = %hex.chars().take(120).collect::<String>(), "undecodable pdu bytes");
            }
        }
    }

    async fn deliver(&mut self, d: crate::pdu::DeliverPdu) {
        if d.udh.app_port.is_some() {
            // WAP push: mms.rs subscribes and owns retrieval.
            let _ = self.urc_tx.send(Urc::WapPush { deliver: d });
            return;
        }
        let staged = if let Some(c) = d.udh.concat {
            self.db
                .stage_inbox_part(&d.sender, c.reference, c.total, c.index, &d.text)
                .await
        } else {
            self.db.insert_inbox_sms(&d.sender, &d.text).await.map(|r| StageResult::Complete(Box::new(r)))
        };
        match staged {
            Ok(StageResult::Complete(row)) => {
                self.events.publish(Event::message(inbox_item_json(&row)));
            }
            Ok(StageResult::Staged) => {}
            Err(e) => tracing::error!(error = %e, "inbox write failed"),
        }
    }

    /// CDS → segment state → rollup. Status transitions publish nothing;
    /// per-client polling covers them (spec §5).
    async fn status_report(&mut self, mr: u8, st: CdsStatus) {
        let found = match self.db.outbox_id_by_mr(mr as i64).await {
            Ok(v) => v,
            Err(_) => None,
        };
        if let Some((oid, sidx)) = found {
            let res = match st {
                CdsStatus::Delivered => {
                    self.db
                        .set_segment_state(oid, sidx, TransportStatus::Delivered, None)
                        .await
                }
                other => {
                    self.db
                        .set_segment_state(oid, sidx, TransportStatus::Failed, Some(other.mapped()))
                        .await
                }
            };
            if res.is_err() {
                tracing::error!(outbox = oid, "segment state write failed");
            }
            if let Ok(Some(row)) = self.db.rollup_outbox(oid).await {
                tracing::info!(
                    outbox = oid,
                    status = row.status.as_str(),
                    "delivery report applied"
                );
            }
        }
    }

    async fn handle_cmti(&mut self, index: u32) {
        match self.wat(&format!("AT+CMGR={index}"), Duration::from_secs(10)).await {
            Ok(lines) => {
                if let Some(hex) = lines.iter().map(|l| l.trim()).find(|l| is_hex(l)) {
                    self.handle_pdu(hex).await;
                } else {
                    tracing::warn!(index, "cmgr returned no pdu");
                }
                // delete regardless of decode outcome; a failed decode is
                // re-imported only if we DIDN'T delete, which would loop
                let _ = self.wat(&format!("AT+CMGD={index}"), Duration::from_secs(5)).await;
            }
            Err(e) => tracing::warn!(index, error = %e, "cmgr failed (message left stored)"),
        }
    }

    // ----- send pipeline ----------------------------------------------------

    async fn send_cycle(&mut self) {
        if self.busy_sending {
            return;
        }
        self.busy_sending = true;
        self.send_cycle_inner().await;
        self.busy_sending = false;
    }

    async fn send_cycle_inner(&mut self) {
        if self.fail_streak >= 3 && !self.ensure_ready().await {
            return;
        }
        let rows = match self.db.take_sendable_outbox(self.cfg.queue_limit).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "outbox claim failed");
                return;
            }
        };
        for row in rows {
            self.send_row(row).await;
        }
    }

    /// Submit one message's unsent segments. Crash resume: segments with
    /// an assigned MR or a settled state are skipped, so a restart only
    /// resends what never got a +CMGS.
    async fn send_row(&mut self, row: crate::types::OutboxRow) {
        let segs = match pdu::split_septets(&row.text, self.cfg.max_segments) {
            Ok(s) => s,
            Err(_) => {
                let _ = self.db.fail_outbox(row.id, "too_long").await;
                return;
            }
        };
        if segs.len() != row.segments.len() {
            let _ = self.db.fail_outbox(row.id, "segment_mismatch").await;
            return;
        }
        // MR space: 16-slot stride keeps concurrent rows' TP-MR disjoint
        // for up to 16-segment messages (queue_limit < stride).
        let base_mr = (row.id as u8).wrapping_mul(16);
        let seg_ref = (row.id & 0xFF) as u8;
        let pdus = match pdu::encode_submit(
            &row.to_num,
            &segs,
            seg_ref,
            base_mr,
            row.want_dr,
            self.cfg.csmp_vp,
        ) {
            Ok(p) => p,
            Err(_) => {
                let _ = self.db.fail_outbox(row.id, "encode_failed").await;
                return;
            }
        };
        for (seg, pdu) in row.segments.iter().zip(pdus.iter()) {
            if seg.mr.is_some() || seg.status != TransportStatus::Pending {
                continue;
            }
            match self.inner.cmgs(pdu.tp_octets, &pdu.hex).await {
                Ok(mr) => {
                    if let Err(e) = self.db.assign_segment_mr(row.id, seg.seg_index, mr as i64).await {
                        tracing::error!(error = %e, "mr write failed");
                    }
                }
                Err(CmgsFail::NoPrompt) => {
                    self.retry_or_fail(&row, "no_prompt").await;
                    return;
                }
                Err(CmgsFail::At(AtError::Cms(c))) if matches!(c, 302 | 331 | 328) => {
                    self.retry_or_fail(&row, &cms_error_string(c)).await;
                    return;
                }
                Err(CmgsFail::At(AtError::Cms(c))) => {
                    let _ = self.db.fail_outbox(row.id, &cms_error_string(c)).await;
                    return;
                }
                Err(CmgsFail::At(AtError::Timeout)) => {
                    let _ = self.db.fail_outbox(row.id, "submit_timeout").await;
                    return;
                }
                Err(CmgsFail::At(AtError::Cme(c))) => {
                    self.retry_or_fail(&row, &format!("cme_error_{c}")).await;
                    return;
                }
                Err(CmgsFail::At(e)) => {
                    self.fail_streak += 1;
                    self.retry_or_fail(&row, &e.to_string()).await;
                    return;
                }
            }
        }
    }

    /// Transient path: attempts were already incremented at claim; past
    /// submit_retries the row fails with the mapped error instead.
    async fn retry_or_fail(&mut self, row: &crate::types::OutboxRow, error: &str) {
        if row.attempts > self.cfg.submit_retries as i64 {
            let _ = self.db.fail_outbox(row.id, error).await;
        } else if let Err(e) = self.db.mark_outbox_retrying(row.id, self.cfg.retry_interval_s, Some(error)).await {
            tracing::error!(error = %e, "retry write failed");
        }
    }

    // ----- status poll -------------------------------------------------------

    async fn status_poll(&mut self) {
        if self.fail_streak >= 3 {
            return; // recovery owns the port while it's healing
        }
        // CPIN
        if let Ok(lines) = self.wat("AT+CPIN?", Duration::from_secs(5)).await {
            if let Some(l) = lines.iter().find(|l| l.starts_with("+CPIN:")) {
                self.sim.state = l[6..].trim().to_ascii_lowercase();
            }
        } else {
            self.sim.state = "unknown".into();
        }
        // CSQ
        if let Ok(lines) = self.wat("AT+CSQ", Duration::from_secs(5)).await {
            if let Some(csq) = lines.iter().find_map(|l| {
                let t = l.strip_prefix("+CSQ:")?.trim();
                t.split(',').next()?.trim().parse::<i64>().ok()
            }) {
                self.net.csq = csq;
            }
        }
        // registration + operator: CEREG first (LTE/NR), CREG fallback
        let mut registered = false;
        for cmd in ["AT+CEREG?", "AT+CREG?"] {
            if let Ok(lines) = self.wat(cmd, Duration::from_secs(5)).await {
                if let Some(stat) = lines.iter().find_map(|l| {
                    let t = l.splitn(2, ':').nth(1)?.trim();
                    let mut it = t.split(',');
                    let _n = it.next()?;
                    it.next()?.trim().parse::<u32>().ok()
                }) {
                    registered = matches!(stat, 1 | 5);
                    if registered {
                        break;
                    }
                }
            }
        }
        self.net.registered = registered;
        // COPS: operator + AcT (quoted operator may contain commas)
        if let Ok(lines) = self.wat("AT+COPS?", Duration::from_secs(5)).await {
            if let Some(l) = lines.iter().find(|l| l.starts_with("+COPS:")).cloned() {
                if let Some((op, act)) = parse_cops(&l) {
                    self.net.operator = op;
                    self.net.rat = act.map(|a| rat_string(a).to_string()).unwrap_or_default();
                }
            }
        }
        // per-profile band info
        match self.cfg.profile {
            ModemProfile::Rm520n => {
                if let Ok(lines) = self.wat("AT+QNWINFO", Duration::from_secs(5)).await {
                    if let Some(band) = lines.iter().find_map(|l| parse_qnwinfo_band(l)) {
                        self.net.band = band;
                    }
                }
            }
            ModemProfile::Sim7600 => {
                if let Ok(lines) = self.wat("AT+CPSI?", Duration::from_secs(5)).await {
                    if let Some(band) = lines.iter().find_map(|l| parse_cpsi_band(l)) {
                        self.net.band = band;
                    }
                }
            }
        }
        // CCID / CNUM / ATI (best-effort, keep last good value)
        // ICCID: Quectel/SIMCom expose it as +QCCID (AT+CCID is not in the
        // RM520N command set); keep the bare form as fallback.
        for cmd in ["AT+QCCID", "AT+CCID"] {
            if let Ok(lines) = self.wat(cmd, Duration::from_secs(5)).await {
                if let Some(iccid) = lines.iter().find_map(|l| {
                    let t = l
                        .trim()
                        .trim_start_matches("+QCCID:")
                        .trim_start_matches("+CCID:")
                        .trim();
                    (t.len() >= 18 && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_digit()))
                        .then(|| t.to_string())
                }) {
                    self.sim.iccid = iccid;
                    break;
                }
            }
        }
        if let Ok(lines) = self.wat("AT+CNUM", Duration::from_secs(5)).await {
            if let Some(n) = lines.iter().find_map(|l| parse_cnum(l)) {
                self.sim.msisdn = n;
            }
        }
        if let Ok(lines) = self.wat("ATI", Duration::from_secs(5)).await {
            let mut it = lines.iter().filter(|l| !l.trim().is_empty());
            if let Some(m) = it.next() {
                self.info.model = m.trim().chars().take(64).collect();
            }
            if let Some(f) = it.last() {
                self.info.fw = f.trim().trim_start_matches("Revision: ").chars().take(64).collect();
            }
        }
        // The modem answered the poll: it is ready (probing/recovering end
        // here; a dead modem bails out at the fail_streak guard above and
        // recovery owns the state instead).
        if self.state != ModemState::Ready {
            self.set_state(ModemState::Ready).await;
        }
        self.publish_snap();
    }

    // ----- recovery ladder (spec §5) ------------------------------------------

    /// Drive the ladder until the modem answers again (true) or the rungs
    /// are exhausted (false — parked unresponsive; ticks retry from rung 1
    /// after recovery_backoff_s).
    async fn ensure_ready(&mut self) -> bool {
        if self.fail_streak < 3 {
            return true;
        }
        self.set_state(ModemState::Recovering).await;

        // rung 1: AT probe burst
        for _ in 0..3 {
            if self.wat("AT", Duration::from_millis(500)).await.is_ok() {
                self.fail_streak = 0;
                self.set_state(ModemState::Ready).await;
                return true;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // rung 2: CFUN reboot → reopen → re-init (+ import)
        let _ = self.wat("AT+CFUN=1,1", Duration::from_secs(5)).await;
        if self.reopen_port(Duration::from_secs(60)).await && self.run_init().await {
            self.fail_streak = 0;
            self.cmgl_import().await;
            self.set_state(ModemState::Ready).await;
            return true;
        }

        // rung 3: GPIO PWRKEY hard power cycle
        if self.cfg.gpio_power_cycle && self.pwrkey_cycle().await {
            if self.reopen_port(Duration::from_secs(90)).await && self.run_init().await {
                self.fail_streak = 0;
                self.cmgl_import().await;
                self.set_state(ModemState::Ready).await;
                return true;
            }
        }

        // rung 4: unresponsive + event; retry from rung 1 after backoff
        self.set_state(ModemState::Unresponsive).await;
        tracing::error!(backoff_s = self.cfg.recovery_backoff_s, "modem unresponsive");
        tokio::time::sleep(Duration::from_secs(self.cfg.recovery_backoff_s.max(1))).await;
        // after the backoff, try rung 1 once more before giving up this call
        for _ in 0..3 {
            if self.wat("AT", Duration::from_millis(500)).await.is_ok() {
                self.fail_streak = 0;
                self.set_state(ModemState::Ready).await;
                return true;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        false
    }

    async fn set_state(&mut self, s: ModemState) {
        if s != self.state {
            self.state = s.clone();
            self.events.publish(Event::modem_state(serde_json::json!({
                "state": s.as_str(),
            })));
        }
        self.publish_snap();
    }

    /// PWRKEY hard cycle via gpio-cdev: active-low key — low ≥ 6 s kills
    /// power, a low pulse ≥ 650 ms powers back on. Runs on a blocking
    /// thread; total time ~11 s.
    async fn pwrkey_cycle(&self) -> bool {
        let gpio = self.cfg.pwrkey_gpio;
        let r = tokio::task::spawn_blocking(move || {
            let mut chip = match gpio_cdev::Chip::new("/dev/gpiochip0") {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "gpiochip0 open failed");
                    return false;
                }
            };
            let line = match chip.get_line(gpio) {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(gpio, error = %e, "pwrkey line missing");
                    return false;
                }
            };
            let handle = match line.request(gpio_cdev::LineRequestFlags::OUTPUT, 1, "cellmatik-pwrkey") {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(gpio, error = %e, "pwrkey claim failed");
                    return false;
                }
            };
            tracing::info!(gpio, "pwrkey hard cycle");
            let press = |ms: u64, v: u8| -> bool {
                if handle.set_value(v).is_err() {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(ms));
                true
            };
            press(8000, 0) && press(1000, 1) && press(700, 0) && press(0, 1)
        })
        .await;
        matches!(r, Ok(true))
    }
}

// ===== parsing helpers (total: best-effort, never panic) ===================

/// Spec §5 CMS error map for outbox/segment `error` strings.
fn cms_error_string(c: u16) -> String {
    match c {
        302 => "network_timeout".into(),
        331 => "no_network_service".into(),
        328 => "congestion".into(),
        500 => "unknown".into(),
        other => other.to_string(),
    }
}

/// 3GPP AcT (COPS/CEREG) → display string.
fn rat_string(act: u32) -> &'static str {
    match act {
        0 | 1 => "gsm",
        2 => "umts",
        3 => "edge",
        4 => "hspa",
        5 | 6 | 7 | 8 => "lte",
        12 | 13 | 14 => "nr",
        _ => "",
    }
}

/// `+COPS: <mode>[,<format>[,"<oper>"[,<AcT>]]]` — quote-aware split.
/// Returns None when no operator is present (unregistered).
fn parse_cops(l: &str) -> Option<(String, Option<u32>)> {
    let t = l.strip_prefix("+COPS:")?.trim();
    let mut fields: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in t.chars() {
        match c {
            '"' => in_q = !in_q,
            ',' if !in_q => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    if fields.len() < 3 {
        return None;
    }
    let oper = fields[2].trim().to_string();
    if oper.is_empty() {
        return None;
    }
    let act = fields.get(3).and_then(|a| a.trim().parse::<u32>().ok());
    Some((oper, act))
}

/// `+QNWINFO: "FDD","B3","LTE",1650` → band token ("B3"/"n78"/...).
fn parse_qnwinfo_band(l: &str) -> Option<String> {
    let t = l.strip_prefix("+QNWINFO:")?.trim();
    let band = t.split(',').nth(1)?.trim().trim_matches('"');
    if band.is_empty() {
        return None;
    }
    Some(band.chars().take(8).collect())
}

/// `+CPSI: LTE,Online,...,Band 3,...` / `5G ... Band n41` → band token.
fn parse_cpsi_band(l: &str) -> Option<String> {
    let t = l.strip_prefix("+CPSI:")?.trim();
    let rest = t.split("Band").nth(1)?;
    let band: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_alphanumeric())
        .take(8)
        .collect();
    if band.is_empty() {
        None
    } else {
        Some(band)
    }
}

/// `+CNUM: "","+15551234567",129` → the +E.164 token.
fn parse_cnum(l: &str) -> Option<String> {
    let t = l.strip_prefix("+CNUM:")?;
    for f in t.split(',') {
        let f = f.trim().trim_matches('"');
        if f.starts_with('+')
            && f.len() >= 8
            && f.len() <= 24
            && f[1..].bytes().all(|b| b.is_ascii_digit())
        {
            return Some(f.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_command_finals() {
        assert!(matches!(classify("OK"), Line::Ok));
        assert!(matches!(classify("ERROR"), Line::PlainError));
        assert!(matches!(classify("+CME ERROR: 100"), Line::Cme(100)));
        assert!(matches!(classify("+CMS ERROR: 302"), Line::Cms(302)));
        assert!(matches!(classify("+CMS ERROR: garbage"), Line::Cms(500)));
        assert!(matches!(classify("+CMGS: 7"), Line::CmgsMr(7)));
        assert!(matches!(classify("random noise"), Line::Data));
        assert!(matches!(classify(""), Line::Data));
    }

    #[test]
    fn classify_urcs() {
        assert!(matches!(
            classify("+CMTI: \"ME\",3"),
            Line::Urc(Urc::Cmti { index: 3 })
        ));
        assert!(matches!(classify("RING"), Line::Urc(Urc::Ring)));
        assert!(matches!(
            classify("+CLIP: \"+15551234567\",129,1"),
            Line::Urc(Urc::Clip { number }) if number == "15551234567"
        ));
        assert!(matches!(
            classify("NO CARRIER"),
            Line::Urc(Urc::NoCarrier { cause: None })
        ));
        assert!(matches!(
            classify("+CEND: 0,17"),
            Line::Urc(Urc::NoCarrier { cause }) if cause.as_deref() == Some("17")
        ));
        assert!(matches!(classify("VOICE CALL: BEGIN"), Line::Urc(Urc::VoiceCallBegin)));
        assert!(matches!(classify("VOICE CALL: END"), Line::Urc(Urc::VoiceCallEnd)));
        assert!(matches!(classify("VOICE CALL: END: 000012"), Line::Urc(Urc::VoiceCallEnd)));
        assert!(matches!(
            classify("+DTMF: 5"),
            Line::Urc(Urc::Dtmf { digits }) if digits == "5"
        ));
        // CDS/CMT URCs are two-line: header now, hex next
        assert!(matches!(classify("+CDS: 24"), Line::PduHeader));
        assert!(matches!(classify("+CMT: 24"), Line::PduHeader));
        // unknown '+' shape is Data — context decides URC vs response
        assert!(matches!(classify("+SOMETHING: 1"), Line::Data));
        assert!(matches!(classify("+CSQ: 21,0"), Line::Data));
    }

    #[test]
    fn hex_detection() {
        assert!(is_hex("079144"));
        assert!(!is_hex(""));
        assert!(!is_hex("079"));
        assert!(!is_hex("07914G"));
        let long = "AB".repeat(501);
        assert!(!is_hex(&long));
    }

    #[test]
    fn line_feed_splits_and_caps() {
        let mut f = LineFeed::default();
        let lines = f.feed(b"AT\r\nOK\r\r\n\n+URC\r\n");
        assert_eq!(lines, vec!["AT", "OK", "+URC"]);
        // a single over-cap line is truncated at the cap, then parsing
        // resyncs normally on the next terminator
        let mut f = LineFeed::default();
        let big = vec![b'A'; LINE_CAP_BYTES + 10];
        f.feed(&big);
        let lines = f.feed(b"\r\nnext\r\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), LINE_CAP_BYTES);
        assert_eq!(lines[1], "next");
    }

    #[test]
    fn two_line_cds_capture_via_handle_line() {
        let (tx, mut rx) = broadcast::channel(8);
        let mut f = LineFeed::default();
        let mut pending = None;
        handle_line("+CDS: 24".into(), &mut pending, &mut f, &tx);
        handle_line("0791440000".into(), &mut pending, &mut f, &tx);
        assert!(matches!(
            rx.try_recv(),
            Ok(Urc::Cds { pdu_hex }) if pdu_hex == "0791440000"
        ));
        // non-hex next line clears the flag and classifies normally
        handle_line("+CDS: 24".into(), &mut pending, &mut f, &tx);
        handle_line("+WEIRD: 1".into(), &mut pending, &mut f, &tx);
        assert!(matches!(rx.try_recv(), Ok(Urc::Other(_))));
    }

    #[test]
    fn at_request_collects_lines_until_ok() {
        let (tx, mut rx) = oneshot::channel::<Result<Vec<String>, AtError>>();
        let mut pending = Some(Pending {
            deadline: Instant::now() + CMD_TIMEOUT,
            lines: Vec::new(),
            kind: PendingKind::At(tx),
        });
        let (utx, _rx) = broadcast::channel(8);
        let mut f = LineFeed::default();
        handle_line("+CSQ: 21,0".into(), &mut pending, &mut f, &utx);
        handle_line("OK".into(), &mut pending, &mut f, &utx);
        assert!(matches!(
            rx.try_recv(),
            Ok(Ok(v)) if v == vec!["+CSQ: 21,0".to_string()]
        ));
        assert!(pending.is_none());
    }

    #[test]
    fn cmgs_flow_lines() {
        let (tx, mut rx) = oneshot::channel::<Result<u16, CmgsFail>>();
        let mut pending = Some(Pending {
            deadline: Instant::now() + CMGS_TOTAL_TIMEOUT,
            lines: Vec::new(),
            kind: PendingKind::Cmgs { phase: 1, pdu_hex: String::new(), mr: None, resp: tx },
        });
        let (utx, _rx) = broadcast::channel(8);
        let mut f = LineFeed::default();
        handle_line("+CMGS: 42".into(), &mut pending, &mut f, &utx);
        handle_line("OK".into(), &mut pending, &mut f, &utx);
        assert!(matches!(rx.try_recv(), Ok(Ok(42))));
    }

    #[test]
    fn error_maps() {
        assert_eq!(cms_error_string(302), "network_timeout");
        assert_eq!(cms_error_string(331), "no_network_service");
        assert_eq!(cms_error_string(328), "congestion");
        assert_eq!(cms_error_string(500), "unknown");
        assert_eq!(cms_error_string(304), "304");
        assert_eq!(rat_string(5), "lte");
        assert_eq!(rat_string(13), "nr");
        assert_eq!(rat_string(99), "");
    }

    #[test]
    fn parsers() {
        assert_eq!(
            parse_cops("+COPS: 0,0,\"T-Mobile USA\",7"),
            Some(("T-Mobile USA".into(), Some(7)))
        );
        assert_eq!(parse_cops("+COPS: 0,0,\"A,B\""), Some(("A,B".into(), None)));
        assert_eq!(parse_cops("+COPS: 0"), None);
        assert_eq!(
            parse_qnwinfo_band("+QNWINFO: \"FDD\",\"B3\",\"LTE\",1650"),
            Some("B3".into())
        );
        assert_eq!(
            parse_cpsi_band("+CPSI: LTE,Online,460-00,0x14A2,185E,EARFCN 1650, Band 3, DL BW:5M"),
            Some("3".into())
        );
        assert_eq!(
            parse_cnum("+CNUM: \"\",\"+15551234567\",129"),
            Some("+15551234567".into())
        );
        assert_eq!(parse_cnum("+CNUM: \"\",\"x\",129"), None);
    }
}



