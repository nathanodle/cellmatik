//! SMS PDU codec — GSM 03.40 submit/deliver/status-report over hex PDUs,
//! hand-rolled GSM-7 (+extension) and UCS-2, semi-octet numbers, 8-bit
//! concatenation UDH, relative VP, SRR bit. Text mode is never used.
//!
//! CONTRACT (spec §5 Send/Inbound/VP + §3 POST /v1/sms 422 shapes):
//!  - `split_septets` is the only segmentation authority: n=1 → ≤160
//!    septets no UDH; n>1 → 153-septet segments with concat UDH; extension
//!    chars (\^{}[]~|€) cost 2 septets. It rejects non-GSM-7 chars with
//!    `PduError::Charset { char, position }` and over-length text with
//!    `PduError::TooLong { chars, max_chars, segments_needed, max_segments }`
//!    — the exact 422 payloads (types::ApiError::unprocessable).
//!  - `encode_submit` produces one PDU per segment with the SRR bit when
//!    `want_srr`, the relative VP field `vp` (TP-VP octet as configured —
//!    the PDU replaces AT+CSMP entirely), 8-bit concat UDH (ref, total= n,
//!    index 1..n), and per-segment TP-MR. TP-MRs are unique among in-flight
//!    messages; the caller (modem worker) passes the reference and base.
//!  - `decode_pdu` is **total over arbitrary bytes** (spec §7): any input,
//!    including hostile SMS from any sender worldwide, returns Ok(PduKind)
//!    or Err(PduError) — never a panic, never an OOB read, never an
//!    unbounded allocation. All length fields go through checked
//!    arithmetic; all slicing is bounds-checked by construction.
//!  - Deliver decode covers GSM-7 (default alphabet + extension tables,
//!    both septet packing with UDH fill bits) and UCS-2 (big-endian,
//!    unaligned), semi-octet sender numbers (including alphanumeric
//!    TON 5 GSM-7 Alpha), TP-SCTS timestamps (semi-octet, year bias 2000,
//!    timezone offset quarters), and UDH IEs 0x00 (concat 8-bit) and 0x05
//!    (application-port 16-bit, dst+src).
//!  - Status-report decode: TP-MR, TP-STATUS per GSM 03.40 §9.2.3.15
//!    (0x00/0x01 delivered — 0x01 is "forwarded, unconfirmable", the SC
//!    makes no further attempts so we count it done; 0x20–0x3F temporary
//!    still trying and 0x60–0x7F temporary final → Unreachable;
//!    0x40–0x5F permanent → Rejected; 0x46 specifically "SM Validity
//!    Period Expired" → Expired; bit 7 set or reserved → Unknown(u8)),
//!    TP-SCTS and TP-DT (discharge time) as RFC 3339.
//!  - `e164` accepts `+` followed by 10–15 digits (leading +/digits only;
//!    spaces/dashes/parens are rejected — the API contract says E.164 or
//!    422, and permissive normalization is how number-spoofing bugs start).
//!  - `validity_seconds` decodes the relative-VP table (spec §5) — the sole
//!    source of the no_delivery_report deadline.
//!
//! SECURITY (spec §7): no unwrap/expect/indexing on decoded data, no
//! unsafe, checked arithmetic everywhere, allocation bounded by the
//! actual input length (never by a claimed length).

use chrono::{FixedOffset, TimeZone};
use serde_json::Value;

// ===== GSM 03.38 7-bit default alphabet (0x00–0x7F) =====
// 0x1B is the extension escape; 0x24 is '¤' (dollar sign lives at 0x02),
// 0x40 is '¡' (at-sign lives at 0x00) — the two classic table mistakes.
const GSM7: [char; 128] = [
    '@', '£', '$', '¥', 'è', 'é', 'ù', 'ì',
    'ò', 'Ç', '\n', 'Ø', 'ø', '\r', 'Å', 'å',
    'Δ', '_', 'Φ', 'Γ', 'Λ', 'Ω', 'Π', 'Ψ',
    'Σ', 'Θ', 'Ξ', '\u{1b}', 'Æ', 'æ', 'ß', 'É',
    ' ', '!', '"', '#', '¤', '%', '&', '\'',
    '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', ':', ';', '<', '=', '>', '?',
    '¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 'Ä', 'Ö', 'Ñ', 'Ü', '§',
    '¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à',
];

// 0x1B extension table (second septet → char).
const GSM7_EXT: [(u8, char); 10] = [
    (0x0A, '\u{c}'), // form feed
    (0x14, '^'),
    (0x28, '{'),
    (0x29, '}'),
    (0x2F, '\\'),
    (0x3C, '['),
    (0x3D, '~'),
    (0x3E, ']'),
    (0x40, '|'),
    (0x65, '€'),
];

/// (septet code, costs two septets via 0x1B escape)
fn char_to_septet(c: char) -> Option<(u8, bool)> {
    for (i, gc) in GSM7.iter().enumerate() {
        if *gc == c {
            return Some((i as u8, false));
        }
    }
    for (code, gc) in GSM7_EXT.iter() {
        if *gc == c {
            return Some((*code, true));
        }
    }
    None
}

// ===== bit packing (septets LSB-first per GSM 03.40 §9.2.3.24) =====

/// Packs 7-bit values into octets, LSB-first; the final partial octet is
/// zero-padded on the high side. Mirror of `unpack_septets`.
fn pack_septets(septets: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((septets.len() * 7 + 7) / 8);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for s in septets {
        acc |= (*s as u32 & 0x7F) << nbits;
        nbits += 7;
        while nbits >= 8 {
            out.push((acc & 0xFF) as u8);
            acc >>= 8;
            nbits -= 8;
        }
    }
    if nbits > 0 {
        out.push((acc & 0xFF) as u8);
    }
    out
}

/// Extracts `count` septets from the bitstream, LSB-first. Total: a short
/// input yields a short result (callers check `septets_fit` when a length
/// is mandatory); no index can panic.
fn unpack_septets(bytes: &[u8], count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let base = i * 7;
        let mut v: u8 = 0;
        for k in 0..7 {
            let bit = base + k;
            let oct = bit / 8;
            let Some(b) = bytes.get(oct) else { return out };
            v |= ((b >> (bit % 8)) & 1) << k;
        }
        out.push(v);
    }
    out
}

/// `count` septets need `count*7` bits — at most `bytes.len()` octets.
/// (No slack: the final partial octet is zero-padded, but the septets
/// themselves must fit; a short UD is malformed, never a panic.)
fn septets_fit(count: usize, bytes: &[u8]) -> bool {
    count
        .checked_mul(7)
        .map(|need| need <= bytes.len().saturating_mul(8))
        .unwrap_or(false)
}

// ===== semi-octet digits (BCD, nibbles swapped) =====

fn hex_of(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Digits (ASCII) → semi-octets; odd count padded with 0xF high nibble.
fn pack_semi_octets(digits: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((digits.len() + 1) / 2);
    let mut i = 0;
    while i + 1 < digits.len() {
        out.push((digits[i] - b'0') | ((digits[i + 1] - b'0') << 4));
        i += 2;
    }
    if i < digits.len() {
        out.push((digits[i] - b'0') | 0xF0);
    }
    out
}

/// Semi-octets → digit string; 0xF padding nibbles are dropped. Invalid
/// (non-decimal) nibbles return None.
fn unpack_semi_digits(bytes: &[u8]) -> Option<String> {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let nibbles = [b & 0x0F, (b >> 4) & 0x0F];
        for n in nibbles {
            if n == 0x0F {
                continue;
            }
            if n > 9 {
                return None;
            }
            s.push((b'0' + n) as char);
        }
    }
    Some(s)
}

// ===== bounds-checked cursor (all decode reads go through this) =====

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd { b, i: 0 }
    }
    fn u8(&mut self) -> Result<u8, PduError> {
        if self.i < self.b.len() {
            let v = self.b[self.i];
            self.i += 1;
            Ok(v)
        } else {
            Err(PduError::Malformed("truncated"))
        }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], PduError> {
        match self.b.len().checked_sub(self.i) {
            Some(rem) if rem >= n => {
                let s = &self.b[self.i..self.i + n];
                self.i += n;
                Ok(s)
            }
            _ => Err(PduError::Malformed("truncated")),
        }
    }
    fn rest(&self) -> &'a [u8] {
        &self.b[self.i.min(self.b.len())..]
    }
}

// ===== timestamps (SCTS / TP-DT: semi-octet BCD, swapped nibbles) =====

/// One semi-octet octet → (first digit, second digit); first digit is the
/// LOW nibble. 0xF or >9 returns None (invalid BCD).
fn bcd2(b: u8) -> Option<u8> {
    let lo = b & 0x0F;
    let hi = (b >> 4) & 0x0F;
    if lo > 9 || hi > 9 {
        None
    } else {
        Some(lo * 10 + hi)
    }
}

/// 7-octet semi-octet timestamp → fixed-width RFC 3339 UTC (db format).
/// Timezone nibbles that fail BCD decode are treated as unknown → +00:00
/// (some carriers emit 0xFF there); date/time nibbles must be valid.
fn semi_timestamp(b: &[u8]) -> Option<String> {
    if b.len() != 7 {
        return None;
    }
    let year = bcd2(b[0])?;
    let mon = bcd2(b[1])?;
    let day = bcd2(b[2])?;
    let hour = bcd2(b[3])?;
    let min = bcd2(b[4])?;
    let sec = bcd2(b[5])?;
    // tz: TS 23.040 §9.2.3.11 — offset in quarter-hours as a semi-octet
    // pair; the tens digit lives in the LOW nibble and its bit 3 is the
    // sign (digits 0x8-0xF = negative, magnitude = digit-8). (e.g. 0x69
    // → tens 0x9 = sign+1, units 6 → −16 quarter-hours = UTC−4, US
    // Eastern daylight.) Units digit > 9 means unknown timezone → UTC.
    let tz = b[6];
    let tens = tz & 0x0F;
    let units = (tz >> 4) & 0x0F;
    let neg = tens & 0x08 != 0;
    let offset_secs: i32 = if units > 9 {
        0
    } else {
        let quarters = i32::from(tens & 0x07) * 10 + i32::from(units);
        let mag = quarters * 900;
        if neg { -mag } else { mag }
    };
    let full_year = if year >= 90 { 1900 + i32::from(year) } else { 2000 + i32::from(year) };
    let naive = chrono::NaiveDate::from_ymd_opt(full_year, u32::from(mon), u32::from(day))?
        .and_hms_opt(u32::from(hour), u32::from(min), u32::from(sec))?;
    let off = FixedOffset::east_opt(offset_secs)?;
    let local = off.from_local_datetime(&naive).single()?;
    Some(
        local
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string(),
    )
}

// ===== public types =====

#[derive(Debug, Clone, PartialEq)]
pub enum PduError {
    /// POST /v1/sms 422 shape: {"error":"too_long",...}
    TooLong { chars: usize, max_chars: usize, segments_needed: u8, max_segments: u8 },
    /// POST /v1/sms 422 shape: {"error":"charset","char":"…","position":n}
    Charset { char: char, position: usize },
    /// Malformed/unsupported PDU or number.
    Malformed(&'static str),
}

impl PduError {
    pub fn to_json(self) -> Value {
        match self {
            PduError::TooLong { chars, max_chars, segments_needed, max_segments } => serde_json::json!({
                "error": "too_long", "chars": chars, "max_chars": max_chars,
                "segments_needed": segments_needed, "max_segments": max_segments,
            }),
            PduError::Charset { char, position } => serde_json::json!({
                "error": "charset", "char": char.to_string(), "position": position,
            }),
            PduError::Malformed(why) => serde_json::json!({ "error": "malformed", "why": why }),
        }
    }
}

/// One submit PDU ready for `AT+CMGS=<octets>`.
#[derive(Debug, Clone, PartialEq)]
pub struct SubmitPdu {
    /// Hex characters, SMSC length octet first, no trailing CR.
    pub hex: String,
    /// TP octet count for CMGS (everything after the SMSC length octet).
    pub tp_octets: usize,
    /// TP-MR — the CDS join key.
    pub tp_mr: u8,
    /// 1-based segment index.
    pub seg_index: u8,
    /// Total segments of the message.
    pub seg_total: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Concat {
    pub reference: u8,
    pub total: u8,
    pub index: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppPort {
    pub dst: u16,
    pub src: u16,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Udh {
    pub concat: Option<Concat>,
    pub app_port: Option<AppPort>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeliverPdu {
    /// E.164 with leading + when numeric; raw alphanumeric string when TON 5.
    pub sender: String,
    /// RFC 3339 UTC.
    pub timestamp: String,
    pub text: String,
    pub udh: Udh,
    /// Raw user-data bytes (used by the WAP-push path for MMS).
    pub ud: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusReport {
    pub mr: u8,
    pub status: CdsStatus,
    /// RFC 3339 UTC.
    pub discharge_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CdsStatus {
    Delivered,
    Expired,
    Unreachable,
    Rejected,
    Unknown(u8),
}

impl CdsStatus {
    /// Spec §5 mapped error strings for outbox/segment `error`.
    pub fn mapped(&self) -> &'static str {
        match self {
            CdsStatus::Delivered => "delivered",
            CdsStatus::Expired => "expired",
            CdsStatus::Unreachable => "unreachable",
            CdsStatus::Rejected => "rejected",
            CdsStatus::Unknown(_) => "unknown_status",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PduKind {
    Deliver(DeliverPdu),
    StatusReport(StatusReport),
    /// Supported but not routed (e.g. reserved TP-MTI).
    Other,
}

// ===== public API =====

/// GSM-7 segmentation plan + charset check. Returns the per-segment
/// character strings (each ≤160/153 septets as applicable).
pub fn split_septets(text: &str, max_segments: u8) -> Result<Vec<String>, PduError> {
    for (pos, c) in text.chars().enumerate() {
        if char_to_septet(c).is_none() {
            return Err(PduError::Charset { char: c, position: pos });
        }
    }
    let cost: usize = text
        .chars()
        .map(|c| {
            let (_, ext) = char_to_septet(c).unwrap_or((0, false));
            if ext { 2 } else { 1 }
        })
        .sum();
    if cost <= 160 && max_segments >= 1 {
        return Ok(vec![text.to_string()]);
    }
    let segments_needed = cost.div_ceil(153);
    if segments_needed > max_segments as usize {
        let max_chars = if max_segments <= 1 { 160 } else { 153 * max_segments as usize };
        return Err(PduError::TooLong {
            chars: text.chars().count(),
            max_chars,
            segments_needed: segments_needed.min(255) as u8,
            max_segments,
        });
    }
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_cost = 0usize;
    for c in text.chars() {
        let cc = match char_to_septet(c) {
            Some((_, true)) => 2,
            _ => 1,
        };
        if cur_cost + cc > 153 {
            out.push(std::mem::take(&mut cur));
            cur_cost = 0;
        }
        cur.push(c);
        cur_cost += cc;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

/// Build one submit PDU per segment. `seg_ref` is the per-boot concat
/// reference; segments of the same message share it.
pub fn encode_submit(
    to: &str,
    segments: &[String],
    seg_ref: u8,
    base_mr: u8,
    want_srr: bool,
    vp: u8,
) -> Result<Vec<SubmitPdu>, PduError> {
    let dest = e164(to)?;
    let digits = dest.get(1..).ok_or(PduError::Malformed("e164"))?.as_bytes().to_vec();
    let total = segments.len();
    if total == 0 || total > 255 {
        return Err(PduError::Malformed("segment count"));
    }
    let total_u8 = total as u8;
    let mut out = Vec::with_capacity(total);
    for (i, seg) in segments.iter().enumerate() {
        // septets (charset already guaranteed by split_septets, but this is
        // a pub fn — check again rather than trust the caller)
        let mut septets: Vec<u8> = Vec::with_capacity(seg.chars().count() * 2);
        for c in seg.chars() {
            match char_to_septet(c) {
                Some((code, false)) => septets.push(code),
                Some((code, true)) => {
                    septets.push(0x1B);
                    septets.push(code);
                }
                None => return Err(PduError::Charset { char: c, position: 0 }),
            }
        }
        // user data: octets (8B UDH + fill + septets) and UDL in septets
        let (ud, udl): (Vec<u8>, u8) = if total > 1 {
            let udh = [0x05u8, 0x00, 0x03, seg_ref, total_u8, (i + 1) as u8];
            let mut bits_out: Vec<u8> = Vec::with_capacity(udh.len() + (septets.len() * 7 + 7) / 8 + 1);
            bits_out.extend_from_slice(&udh);
            let fill = (7 - (udh.len() * 8) % 7) % 7; // 6-octet UDH → 1 fill bit
            let udh_septets = (udh.len() * 8 + 6) / 7;
            let mut packed = pack_septets(&septets);
            // prepend fill bits: rebuild via bit accumulation for exactness
            if fill > 0 {
                let mut acc: u32 = 0;
                let mut nbits: u32 = 0;
                let mut repacked: Vec<u8> = Vec::with_capacity(packed.len() + 1);
                for _ in 0..fill {
                    acc <<= 1;
                    nbits += 1;
                }
                for b in packed.drain(..) {
                    acc |= (b as u32) << nbits;
                    nbits += 8;
                    while nbits >= 8 {
                        repacked.push((acc & 0xFF) as u8);
                        acc >>= 8;
                        nbits -= 8;
                    }
                }
                if nbits > 0 {
                    repacked.push((acc & 0xFF) as u8);
                }
                packed = repacked;
            }
            bits_out.extend_from_slice(&packed);
            let udl_septets = udh_septets + septets.len();
            (bits_out, udl_septets as u8)
        } else {
            (pack_septets(&septets), septets.len() as u8)
        };
        let fo = 0x01u8 // SMS-SUBMIT
            | 0x10 // VPF relative
            | if want_srr { 0x20 } else { 0x00 }
            | if total > 1 { 0x40 } else { 0x00 }; // UDHI
        let mut tpdu: Vec<u8> = Vec::with_capacity(14 + ud.len());
        tpdu.push(fo);
        tpdu.push(base_mr.wrapping_add(i as u8));
        tpdu.push(digits.len() as u8);
        tpdu.push(0x91); // TOA: international / ISDN
        tpdu.extend_from_slice(&pack_semi_octets(&digits));
        tpdu.push(0x00); // PID
        tpdu.push(0x00); // DCS: GSM-7
        tpdu.push(vp);
        tpdu.push(udl);
        tpdu.extend_from_slice(&ud);
        let mut hex = String::with_capacity(2 + tpdu.len() * 2);
        hex.push_str("00"); // SMSC length octet: no SMSC
        for b in &tpdu {
            hex.push_str(&format!("{:02X}", b));
        }
        out.push(SubmitPdu {
            tp_octets: tpdu.len(),
            hex,
            tp_mr: base_mr.wrapping_add(i as u8),
            seg_index: (i + 1) as u8,
            seg_total: total_u8,
        });
    }
    Ok(out)
}

/// Decode one inbound PDU (deliver or status report). Total function.
pub fn decode_pdu(hex: &str) -> Result<PduKind, PduError> {
    // strip inter-command whitespace; validate hex; bounded allocation
    let mut bytes: Vec<u8> = Vec::with_capacity(hex.len() / 2);
    let mut hi: Option<u8> = None;
    for c in hex.bytes() {
        let d = match c {
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => hex_of(c),
        };
        let d = match d {
            Some(d) => d,
            None => return Err(PduError::Malformed("hex")),
        };
        match hi {
            None => hi = Some(d),
            Some(h) => {
                bytes.push((h << 4) | d);
                hi = None;
            }
        }
    }
    if hi.is_some() {
        return Err(PduError::Malformed("hex length"));
    }
    let mut rd = Rd::new(&bytes);
    let smsc_len = rd.u8()? as usize;
    rd.take(smsc_len)?; // SMSC address bytes (ignored — routing uses OA only)
    let fo = rd.u8()?;
    match fo & 0x03 {
        0 => decode_deliver(&mut rd, fo & 0x40 != 0).map(PduKind::Deliver),
        2 => decode_status_report(&mut rd).map(PduKind::StatusReport),
        _ => Ok(PduKind::Other),
    }
}

fn decode_deliver(rd: &mut Rd, udhi: bool) -> Result<DeliverPdu, PduError> {
    let oa_len = rd.u8()? as usize;
    let oa_toa = rd.u8()?;
    let alpha = (oa_toa & 0x70) == 0x50;
    // numeric: ceil(len/2) octets; alphanumeric: len counts septets → ceil(7*len/8)
    let oa_bytes = if alpha {
        let octets = oa_len
            .checked_mul(7)
            .and_then(|b| b.checked_add(7))
            .map(|b| b / 8)
            .ok_or(PduError::Malformed("address"))?;
        rd.take(octets)?
    } else {
        rd.take(oa_len / 2 + (oa_len & 1))?
    };
    let sender = if alpha {
        decode_gsm7_text(&unpack_septets(oa_bytes, oa_len))
    } else {
        let digits = unpack_semi_digits(oa_bytes).ok_or(PduError::Malformed("address"))?;
        if (oa_toa & 0x70) == 0x10 {
            format!("+{}", digits) // TON 1: international
        } else {
            digits
        }
    };
    let _pid = rd.u8()?;
    let dcs = rd.u8()?;
    let scts = rd.take(7)?;
    let timestamp = semi_timestamp(scts).ok_or(PduError::Malformed("scts"))?;
    let udl = rd.u8()? as usize;
    let ud = rd.rest();

    // alphabet bits (TS 23.038); 10xx/11xx coding groups → raw octets
    let raw = matches!(dcs & 0xC0, 0x80 | 0xC0) || (dcs & 0x0C) == 0x0C;
    let ucs2 = !raw && (dcs & 0x0C) == 0x08;
    let gsm7 = !raw && !ucs2 && (dcs & 0x0C) == 0x00;

    let (udh, udh_octets) = if udhi { parse_udh(ud)? } else { (Udh::default(), 0) };

    let text: String;
    let ud_out: Vec<u8>;
    if gsm7 {
        if !septets_fit(udl, ud) || udl < (udh_octets * 8 + 6) / 7 {
            return Err(PduError::Malformed("udl"));
        }
        let all = unpack_septets(ud, udl);
        let udh_septets = (udh_octets * 8 + 6) / 7;
        let text_septets = all
            .get(udh_septets..)
            .ok_or(PduError::Malformed("udl"))?;
        text = decode_gsm7_text(text_septets);
        ud_out = text_septets.to_vec();
    } else if ucs2 {
        if udl > ud.len() {
            return Err(PduError::Malformed("udl"));
        }
        let start = udh_octets.min(udl);
        let po = &ud[start..udl];
        if po.len() % 2 != 0 {
            return Err(PduError::Malformed("udl"));
        }
        let units: Vec<u16> = po
            .chunks(2)
            .map(|p| ((p[0] as u16) << 8) | p[1] as u16)
            .collect();
        text = String::from_utf16_lossy(&units);
        ud_out = po.to_vec();
    } else {
        if udl > ud.len() {
            return Err(PduError::Malformed("udl"));
        }
        let start = udh_octets.min(udl);
        text = String::new();
        ud_out = ud[start..udl].to_vec();
    }
    Ok(DeliverPdu { sender, timestamp, text, udh, ud: ud_out })
}

fn decode_status_report(rd: &mut Rd) -> Result<StatusReport, PduError> {
    let mr = rd.u8()?;
    let ra_len = rd.u8()? as usize;
    if ra_len > 0 {
        let _toa = rd.u8()?;
        rd.take(ra_len / 2 + (ra_len & 1))?;
    }
    let _scts = rd.take(7)?; // submission time; the API surfaces discharge only
    let dt = rd.take(7)?;
    let st = rd.u8()?;
    // trailing TP-PI/optional fields (if any) are not needed
    let discharge_at = semi_timestamp(dt);
    Ok(StatusReport { mr, status: map_st(st), discharge_at })
}

/// TS 23.040 §9.2.3.15 TP-ST → CdsStatus (see module doc for the mapping).
fn map_st(st: u8) -> CdsStatus {
    if st & 0x80 != 0 {
        return CdsStatus::Unknown(st);
    }
    match st {
        0x00 | 0x01 => CdsStatus::Delivered, // 0x01: forwarded, delivery unconfirmable
        0x02..=0x1F => CdsStatus::Unknown(st),
        0x20..=0x3F => CdsStatus::Unreachable, // temporary error, SC still trying
        0x46 => CdsStatus::Expired,            // SM validity period expired
        0x40..=0x5F => CdsStatus::Rejected,    // permanent error
        0x60..=0x7F => CdsStatus::Unreachable, // temporary error, final
        _ => CdsStatus::Unknown(st),           // unreachable in practice (bit7 handled above)
    }
}

/// UDH at the head of UD: returns parsed IEs and octets consumed
/// (UDHL byte + UDHL bytes). Total: any claim beyond the buffer is
/// Malformed, never a panic.
fn parse_udh(ud: &[u8]) -> Result<(Udh, usize), PduError> {
    let mut rd = Rd::new(ud);
    let udhl = rd.u8()? as usize;
    let total = 1 + udhl;
    if total > ud.len() {
        return Err(PduError::Malformed("udh"));
    }
    let mut udh = Udh::default();
    while rd.i < total {
        let iei = rd.u8()?;
        let ielen = rd.u8()? as usize;
        let ie = rd.take(ielen)?;
        if rd.i > total {
            return Err(PduError::Malformed("udh ie"));
        }
        match (iei, ielen) {
            (0x00, 3) if ie.len() == 3 => {
                udh.concat = Some(Concat { reference: ie[0], total: ie[1], index: ie[2] });
            }
            (0x05, 4) if ie.len() == 4 => {
                udh.app_port = Some(AppPort {
                    dst: ((ie[0] as u16) << 8) | ie[1] as u16,
                    src: ((ie[2] as u16) << 8) | ie[3] as u16,
                });
            }
            _ => {} // unknown IE: skipped (bounded by udh length)
        }
    }
    Ok((udh, total))
}

/// GSM-7 septet values → text; 0x1B selects the extension table,
/// unmapped extension codes and a trailing bare 0x1B become U+FFFD/skip.
fn decode_gsm7_text(septets: &[u8]) -> String {
    let mut s = String::with_capacity(septets.len());
    let mut i = 0;
    while i < septets.len() {
        let v = septets[i] & 0x7F;
        if v == 0x1B {
            if i + 1 < septets.len() {
                let next = septets[i + 1] & 0x7F;
                let c = GSM7_EXT.iter().find(|(code, _)| *code == next).map(|(_, c)| *c);
                match c {
                    Some(c) => s.push(c),
                    None => s.push('\u{fffd}'),
                }
                i += 2;
            } else {
                i += 1; // dangling escape: dropped
            }
        } else {
            s.push(GSM7[v as usize]);
            i += 1;
        }
    }
    s
}

/// E.164 validation: `+` then 10–15 digits. Strict — no silent cleanup.
pub fn e164(input: &str) -> Result<String, PduError> {
    let mut chars = input.chars();
    match chars.next() {
        Some('+') => {}
        _ => return Err(PduError::Malformed("e164")),
    }
    let mut n = 0;
    for c in chars {
        if !c.is_ascii_digit() {
            return Err(PduError::Malformed("e164"));
        }
        n += 1;
    }
    if (10..=15).contains(&n) {
        Ok(input.to_string())
    } else {
        Err(PduError::Malformed("e164"))
    }
}

/// Relative-VP decode (spec §5 table) → seconds.
pub fn validity_seconds(vp: u8) -> u64 {
    match vp {
        0..=143 => (vp as u64 + 1) * 5 * 60,
        144..=167 => 12 * 3600 + (vp as u64 - 143) * 30 * 60,
        168..=196 => (vp as u64 - 166) * 86400,
        _ => (vp as u64 - 192) * 7 * 86400,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only: wrap a submit PDU's UD (UDL + packed user data) in a
    /// deliver-shaped PDU so the inbound decoder can round-trip it.
    /// (decode_pdu routes MTI 1 submits to PduKind::Other by design.)
    fn wrap_as_deliver(p: &SubmitPdu, oa: &str) -> String {
        let hex = &p.hex;
        let n_octets = hex.len() / 2;
        let mut tpdu: Vec<u8> = Vec::with_capacity(n_octets);
        for i in 1..n_octets {
            // skip the leading "00" SMSC-length octet: tpdu[0] is the first octet
            let s = hex.get(i * 2..i * 2 + 2).unwrap();
            tpdu.push(u8::from_str_radix(s, 16).unwrap());
        }
        // tpdu: fo mr da_len toa <da> pid dcs vp udl <ud>
        let da_len = tpdu[2] as usize;
        let ud_off = 8 + (da_len + 1) / 2;
        let udl = tpdu[ud_off - 1];
        let ud = &tpdu[ud_off..];
        let digits = oa.as_bytes()[1..].to_vec();
        let mut out: Vec<u8> = vec![if p.seg_total > 1 { 0x40 } else { 0x00 }];
        out.push(digits.len() as u8);
        out.push(0x91);
        out.extend_from_slice(&pack_semi_octets(&digits));
        out.push(0x00); // PID
        out.push(0x00); // DCS GSM-7
        out.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]); // SCTS
        out.push(udl);
        out.extend_from_slice(ud);
        let mut full = String::from("00");
        for b in &out {
            full.push_str(&format!("{:02X}", b));
        }
        full
    }

    fn decode_submit_via_deliver(p: &SubmitPdu) -> DeliverPdu {
        match decode_pdu(&wrap_as_deliver(p, "+15551234567")).unwrap() {
            PduKind::Deliver(d) => d,
            other => panic!("expected Deliver, got {:?}", other),
        }
    }

    // ---- split_septets ----

    #[test]
    fn split_single() {
        assert_eq!(split_septets("Hello", 10).unwrap(), vec!["Hello".to_string()]);
        let s160: String = "a".repeat(160);
        assert_eq!(split_septets(&s160, 10).unwrap().len(), 1);
    }

    #[test]
    fn split_multi_boundary() {
        let s161: String = "a".repeat(161);
        let segs = split_septets(&s161, 10).unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].len(), 153);
        assert_eq!(segs[1].len(), 8);
    }

    #[test]
    fn split_extension_costs_double() {
        // 10 '^' = 20 septets + 140 'a' = 160 total → still single
        let mut t = "a".repeat(140);
        t.push_str(&"^".repeat(10));
        assert_eq!(split_septets(&t, 10).unwrap().len(), 1);
        // one more char → 162 septets → two segments
        t.push('a');
        assert_eq!(split_septets(&t, 10).unwrap().len(), 2);
    }

    #[test]
    fn split_too_long_shape() {
        let t: String = "a".repeat(1531); // needs 11×153+1 → 11 segments? 1531/153 = 10.007 → 11
        let err = split_septets(&t, 10).unwrap_err();
        match err {
            PduError::TooLong { chars, max_chars, segments_needed, max_segments } => {
                assert_eq!(chars, 1531);
                assert_eq!(max_chars, 1530);
                assert_eq!(segments_needed, 11);
                assert_eq!(max_segments, 10);
            }
            other => panic!("expected TooLong, got {:?}", other),
        }
    }

    #[test]
    fn split_charset_error_position() {
        let mut t = String::from("hello world hello world hello world hello ");
        t.push('🙂');
        match split_septets(&t, 10).unwrap_err() {
            PduError::Charset { char, position } => {
                assert_eq!(char, '🙂');
                assert_eq!(position, 42);
            }
            other => panic!("expected Charset, got {:?}", other),
        }
    }

    // ---- e164 ----

    #[test]
    fn e164_valid_and_invalid() {
        assert!(e164("+15551234567").is_ok());
        assert!(e164("15551234567").is_err()); // missing +
        assert!(e164("+155512345").is_err()); // 9 digits
        assert!(e164("+1555123456789012").is_err()); // 16 digits
        assert!(e164("+1 5551234567").is_err()); // space
        assert!(e164("+1-555-1234567").is_err()); // dash
        assert!(e164("+1555𝟏234567").is_err()); // non-ASCII digit
        assert!(e164("").is_err());
    }

    // ---- validity_seconds ----

    #[test]
    fn validity_table() {
        assert_eq!(validity_seconds(0), 300);
        assert_eq!(validity_seconds(143), 43200); // (143+1)*5min = 12h
        assert_eq!(validity_seconds(144), 45000); // 12h + 30min
        assert_eq!(validity_seconds(167), 86400); // 12h + 24*30min = 24h
        assert_eq!(validity_seconds(168), 172800);
        assert_eq!(validity_seconds(196), 30 * 86400);
        assert_eq!(validity_seconds(197), 5 * 7 * 86400);
        assert_eq!(validity_seconds(255), 63 * 7 * 86400);
    }

    // ---- golden vectors ----

    #[test]
    fn submit_hello_golden() {
        // "Hello" packs to C8 32 9B FD 06 (the canonical GSM-7 packing);
        // destination +15551234567 → 51 55 21 43 65 F7 (semi-octets, F pad).
        let pdus = encode_submit(
            "+15551234567",
            &["Hello".to_string()],
            0,
            0,
            true, // SRR
            0xA7, // 24h relative VP
        )
        .unwrap();
        assert_eq!(pdus.len(), 1);
        let p = &pdus[0];
        assert_eq!(
            p.hex,
            "0031000B915155214365F70000A705C8329BFD06".to_string()
        );
        assert_eq!(p.tp_octets, 19);
        assert_eq!(p.tp_mr, 0);
        assert_eq!(p.seg_index, 1);
        assert_eq!(p.seg_total, 1);
    }

    #[test]
    fn roundtrip_gsm7_alphabet() {
        // every representable char except the bare ESC itself
        let mut text = String::new();
        for (i, c) in GSM7.iter().enumerate() {
            if i != 0x1B {
                text.push(*c);
            }
        }
        for c in GSM7_EXT.iter().map(|(_, c)| *c) {
            text.push(c);
        }
        let segs = split_septets(&text, 20).unwrap();
        let pdus = encode_submit("+15551234567", &segs, 42, 7, true, 0xA7).unwrap();
        // 127 basic + 10 extension×2 = 147 septets → fits one segment (no UDH)
        assert_eq!(pdus.len(), 1);
        let mut reassembled = String::new();
        for (i, p) in pdus.iter().enumerate() {
            let d = decode_submit_via_deliver(p);
            assert_eq!(d.text, segs[i]);
            match pdus.len() {
                1 => assert_eq!(d.udh, Udh::default()),
                _ => {
                    let cat = d.udh.concat.expect("concat present");
                    assert_eq!(cat.reference, 42);
                    assert_eq!(cat.total, pdus.len() as u8);
                    assert_eq!(cat.index, (i + 1) as u8);
                }
            }
            reassembled.push_str(&d.text);
        }
        assert_eq!(reassembled, text);
    }

    #[test]
    fn roundtrip_extension_chars_in_multi_segment() {
        let mut text = String::new();
        for i in 0..400 {
            let c = match i % 4 {
                0 => '^',
                1 => '€',
                2 => 'a',
                _ => '~',
            };
            text.push(c);
        }
        let segs = split_septets(&text, 10).unwrap();
        assert!(segs.len() > 2);
        let pdus = encode_submit("+15551234567", &segs, 9, 200, false, 0x00).unwrap();
        let mut got = String::new();
        for p in &pdus {
            got.push_str(&decode_submit_via_deliver(p).text);
        }
        assert_eq!(got, text);
    }

    #[test]
    fn concat_udh_layout() {
        // two-segment send: UDH = 05 00 03 <ref> 02 01/02, 1 fill bit after
        // the 48-bit UDH; UDL counts 7 UDH septets + text septets.
        let segs = split_septets(&"b".repeat(200), 5).unwrap();
        assert_eq!(segs.len(), 2);
        let pdus = encode_submit("+15551234567", &segs, 0xAB, 0, false, 0x00).unwrap();
        for (i, p) in pdus.iter().enumerate() {
            let d = decode_submit_via_deliver(p);
            let cat = d.udh.concat.unwrap();
            assert_eq!((cat.reference, cat.total, cat.index), (0xAB, 2, (i + 1) as u8));
            assert_eq!(d.text, segs[i]);
        }
    }

    #[test]
    fn real_att_deliver_decodes() {
        // Shape captured live from a real carrier SMSC 2026-10-09 (numbers
        // anonymized): 50-octet SMS-DELIVER the parser once rejected as
        // "undecodable" — the SCTS timezone octet 0x69 (UTC−4) exploded
        // the old tz decoding. UDL=26 septets / 23 UD octets, SMSC present.
        let hex = "0791312155153254040B915155214365F70000620190509171691AE3329BDD0ED3D36B90BC1C6683D8EF375C1C1EAF417619";
        match decode_pdu(hex) {
            Ok(PduKind::Deliver(d)) => {
                assert_eq!(d.sender, "+15551234567");
                assert_eq!(d.text, "cellmatik real loopback v2");
                assert_eq!(d.ud.len(), 26); // text septets
                // SCTS 05:19:17 local, tz 0x69 = UTC−4 → 09:19:17Z
                assert_eq!(d.timestamp, "2026-10-09T09:19:17.000Z");
            }
            other => panic!("decode returned {other:?}"),
        }
    }

    #[test]
    fn real_att_stored_deliver_decodes() {
        // Stored-ME deliver found at boot (prior session's loopback,
        // 54 octets, numbers anonymized): UDL=30 septets / 27 UD octets.
        let hex = "0791312155153254040B915155214365F70000620180223443691ECCF71B2E0E8FD7A079996D6ED1CB733AC82C7FB741ED37B9DC7601";
        match decode_pdu(hex) {
            Ok(PduKind::Deliver(d)) => {
                assert_eq!(d.sender, "+15551234567");
                assert_eq!(d.text, "Loopback self-test from modem.");
                assert_eq!(d.ud.len(), 30); // text septets
            }
            other => panic!("decode returned {other:?}"),
        }
    }

    #[test]
    fn deliver_ucs2_golden() {
        // hand-built: SMSC=none, fo=04 (MMS), OA=+1234567890, DCS=08 (UCS-2),
        // SCTS 2026-10-09 12:34:56 UTC, text "€" (U+20AC).
        let hex = "00040A9121436587090008620190214365000220AC";
        match decode_pdu(hex).unwrap() {
            PduKind::Deliver(d) => {
                assert_eq!(d.sender, "+1234567890");
                assert_eq!(d.timestamp, "2026-10-09T12:34:56.000Z");
                assert_eq!(d.text, "€");
                assert_eq!(d.ud, vec![0x20, 0xAC]);
                assert_eq!(d.udh, Udh::default());
            }
            other => panic!("expected Deliver, got {:?}", other),
        }
    }

    #[test]
    fn deliver_alphanumeric_sender() {
        // OA TON 5: address bytes are GSM-7 septets. "A" = 1 septet 0x41.
        let mut tpdu: Vec<u8> = vec![0x04, 0x01, 0xD0, 0x41, 0x00, 0x00];
        // SCTS: 26-10-09 12:34:56 UTC
        tpdu.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]);
        tpdu.push(0x00); // UDL 0
        let mut full = String::from("00");
        for b in &tpdu {
            full.push_str(&format!("{:02X}", b));
        }
        match decode_pdu(&full).unwrap() {
            PduKind::Deliver(d) => {
                assert_eq!(d.sender, "A");
                assert_eq!(d.timestamp, "2026-10-09T12:34:56.000Z");
                assert_eq!(d.text, "");
            }
            other => panic!("expected Deliver, got {:?}", other),
        }
    }

    #[test]
    fn deliver_wap_push_ud_and_app_port() {
        // 8-bit DCS (0x04) with 16-bit app-port UDH (0x05 04 0B 84 0B 84 =
        // dst 2948, src 2948) and 3 WSP payload bytes 01 06 83.
        let ud: Vec<u8> = [0x06u8, 0x05, 0x04, 0x0B, 0x84, 0x0B, 0x84, 0x01, 0x06, 0x83].to_vec();
        let mut tpdu: Vec<u8> = vec![0x44, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0x04];
        tpdu.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]);
        tpdu.push(ud.len() as u8);
        tpdu.extend_from_slice(&ud);
        let mut full = String::from("00");
        for b in &tpdu {
            full.push_str(&format!("{:02X}", b));
        }
        match decode_pdu(&full).unwrap() {
            PduKind::Deliver(d) => {
                assert_eq!(d.sender, "+1234567890");
                let ap = d.udh.app_port.expect("app port");
                assert_eq!(ap.dst, 2948);
                assert_eq!(ap.src, 2948);
                assert_eq!(d.ud, vec![0x01, 0x06, 0x83]);
                assert_eq!(d.text, "");
            }
            other => panic!("expected Deliver, got {:?}", other),
        }
    }

    /// Regression (e2e-found): UDL claiming 13 septets but only 11 UD
    /// octets must be a clean Malformed error — never a panicking index
    /// (spec §7: decode is total over arbitrary bytes).
    #[test]
    fn deliver_short_ud_is_malformed_not_panic() {
        let mut tpdu: Vec<u8> = vec![0x00, 0x0B, 0x91]; // fo, OA len 11, toa
        tpdu.extend_from_slice(&[0x51, 0x55, 0x99, 0x78, 0x56, 0x43]); // +15559876543
        tpdu.extend_from_slice(&[0x00, 0x00]); // PID, DCS (GSM-7)
        tpdu.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]); // SCTS
        tpdu.push(13); // UDL: 13 septets ⇒ needs 12 octets…
        tpdu.extend_from_slice(&[0xE8; 11]); // …but only 11 present
        let mut full = String::from("00");
        for b in &tpdu {
            full.push_str(&format!("{:02X}", b));
        }
        match decode_pdu(&full) {
            Err(PduError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {:?}", other.map(|_| ())),
        }
        // and the direct helper: short input yields a short result
        // (11 octets = 88 bits = 12 full septets; the 13th is truncated)
        assert_eq!(unpack_septets(&[0xFF; 11], 13).len(), 12);
    }

    #[test]
    fn status_report_golden_and_mapping() {
        // SMSC none, fo=02 (SRR+MTI SR), MR=42, RA=+1234567890 11-digit? use 10,
        // SCTS/DT = 2026-10-09 12:34:56, ST=00.
        let mut tpdu: Vec<u8> = vec![0x02, 0x42, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09];
        tpdu.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]); // SCTS
        tpdu.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x75, 0x00]); // DT 12:34:57
        tpdu.push(0x00); // ST delivered
        let mut full = String::from("00");
        for b in &tpdu {
            full.push_str(&format!("{:02X}", b));
        }
        match decode_pdu(&full).unwrap() {
            PduKind::StatusReport(sr) => {
                assert_eq!(sr.mr, 0x42);
                assert_eq!(sr.status, CdsStatus::Delivered);
                assert_eq!(sr.discharge_at.as_deref(), Some("2026-10-09T12:34:57.000Z"));
            }
            other => panic!("expected StatusReport, got {:?}", other),
        }
        // TP-ST classes
        assert_eq!(map_st(0x00), CdsStatus::Delivered);
        assert_eq!(map_st(0x01), CdsStatus::Delivered);
        assert_eq!(map_st(0x02), CdsStatus::Unknown(0x02));
        assert_eq!(map_st(0x20), CdsStatus::Unreachable); // congestion, still trying
        assert_eq!(map_st(0x21), CdsStatus::Unreachable); // SME busy
        assert_eq!(map_st(0x3F), CdsStatus::Unreachable);
        assert_eq!(map_st(0x40), CdsStatus::Rejected); // permanent
        assert_eq!(map_st(0x46), CdsStatus::Expired); // validity period expired
        assert_eq!(map_st(0x49), CdsStatus::Rejected); // SM does not exist
        assert_eq!(map_st(0x60), CdsStatus::Unreachable); // temporary, final
        assert_eq!(map_st(0x7F), CdsStatus::Unreachable);
        assert_eq!(map_st(0x80), CdsStatus::Unknown(0x80));
        assert_eq!(map_st(0xFF), CdsStatus::Unknown(0xFF));
    }

    #[test]
    fn status_report_empty_ra() {
        let mut tpdu: Vec<u8> = vec![0x02, 0x07, 0x00]; // MR, RA len 0
        tpdu.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]);
        tpdu.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]);
        tpdu.push(0x46);
        let mut full = String::from("00");
        for b in &tpdu {
            full.push_str(&format!("{:02X}", b));
        }
        match decode_pdu(&full).unwrap() {
            PduKind::StatusReport(sr) => {
                assert_eq!(sr.mr, 0x07);
                assert_eq!(sr.status, CdsStatus::Expired);
            }
            other => panic!("expected StatusReport, got {:?}", other),
        }
    }

    // ---- adversarial inputs (all must Err, never panic) ----

    #[test]
    fn adversarial_all_prefixes_err() {
        let good = "000C915344872040F500009902169434240055F4F29C0E".to_string();
        // every strict prefix shorter than the PDU must not panic; most Err
        for n in 0..good.len() / 2 {
            let mut s = String::new();
            for i in 0..n {
                s.push_str(&good[i * 2..i * 2 + 2]);
            }
            let _ = decode_pdu(&s); // must not panic
        }
    }

    #[test]
    fn adversarial_shapes() {
        assert!(decode_pdu("").is_err());
        assert!(decode_pdu("0").is_err()); // odd hex
        assert!(decode_pdu("0G").is_err()); // non-hex
        // 100 KB junk whose MTI happens to be valid: bounded scan, Ok(Other)
        assert_eq!(decode_pdu(&"41".repeat(100_000)).unwrap(), PduKind::Other);
        // 100 KB that cannot decode: SCTS month nibbles 1/4 → month 14 → Err
        let junk = format!("00040A91{}", "41".repeat(100_000));
        assert!(decode_pdu(&junk).is_err());
        // MTI reserved → Other (not routed), still no panic
        assert_eq!(decode_pdu("0003").unwrap(), PduKind::Other);
        // UDH claiming more octets than the UD holds
        let ud_bad = [0x7Fu8, 0x00, 0x03, 0x01, 0x02, 0x01];
        let mut tpdu: Vec<u8> = vec![0x40, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0x00];
        tpdu.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]);
        tpdu.push(ud_bad.len() as u8);
        tpdu.extend_from_slice(&ud_bad);
        let mut full = String::from("00");
        for b in &tpdu {
            full.push_str(&format!("{:02X}", b));
        }
        assert!(decode_pdu(&full).is_err());
        // UDL pointing past the end (7-bit claim: 200 septets, 10 octets present)
        let mut tpdu2: Vec<u8> = vec![0x00, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0x00];
        tpdu2.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]);
        tpdu2.push(200);
        tpdu2.extend_from_slice(&[0xC8, 0x32, 0x9B, 0xFD, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut full2 = String::from("00");
        for b in &tpdu2 {
            full2.push_str(&format!("{:02X}", b));
        }
        assert!(decode_pdu(&full2).is_err());
        // garbage DCS (0xC1: reserved coding group) → raw octets, text empty
        let mut tpdu3: Vec<u8> = vec![0x00, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0xC1];
        tpdu3.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]);
        tpdu3.push(3);
        tpdu3.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        let mut full3 = String::from("00");
        for b in &tpdu3 {
            full3.push_str(&format!("{:02X}", b));
        }
        match decode_pdu(&full3).unwrap() {
            PduKind::Deliver(d) => {
                assert_eq!(d.text, "");
                assert_eq!(d.ud, vec![0xAB, 0xCD, 0xEF]);
            }
            other => panic!("expected Deliver, got {:?}", other),
        }
        // zero-length UD
        let mut tpdu4: Vec<u8> = vec![0x00, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0x00];
        tpdu4.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]);
        tpdu4.push(0);
        let mut full4 = String::from("00");
        for b in &tpdu4 {
            full4.push_str(&format!("{:02X}", b));
        }
        match decode_pdu(&full4).unwrap() {
            PduKind::Deliver(d) => {
                assert_eq!(d.text, "");
                assert_eq!(d.ud, Vec::<u8>::new());
            }
            other => panic!("expected Deliver, got {:?}", other),
        }
    }

    #[test]
    fn adversarial_ie_bounds() {
        // IE header claims 3 bytes but only 1 present inside UDHL
        let ud = [0x03u8, 0x00, 0x03, 0x01];
        assert!(parse_udh(&ud).is_err());
        // IE header itself truncated
        let ud2 = [0x02u8, 0x00];
        assert!(parse_udh(&ud2).is_err());
        // well-formed concat IE parses
        let ud3 = [0x05u8, 0x00, 0x03, 0xAB, 0x02, 0x01];
        let (udh, used) = parse_udh(&ud3).unwrap();
        assert_eq!(used, 6);
        assert_eq!(udh.concat, Some(Concat { reference: 0xAB, total: 2, index: 1 }));
    }

    #[test]
    fn adversarial_timestamps() {
        // invalid BCD in date → Err via deliver; unknown tz nibble → UTC
        let mut tpdu: Vec<u8> = vec![0x00, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0x00];
        tpdu.extend_from_slice(&[0xFF, 0x01, 0x90, 0x21, 0x43, 0x65, 0x00]); // year nibbles F
        tpdu.push(0);
        let mut full = String::from("00");
        for b in &tpdu {
            full.push_str(&format!("{:02X}", b));
        }
        assert!(decode_pdu(&full).is_err());
        // tz 0xFF (unknown) → offset 0, still decodes
        let mut tpdu2: Vec<u8> = vec![0x00, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0x00];
        tpdu2.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0xFF]);
        tpdu2.push(0);
        let mut full2 = String::from("00");
        for b in &tpdu2 {
            full2.push_str(&format!("{:02X}", b));
        }
        match decode_pdu(&full2).unwrap() {
            PduKind::Deliver(d) => assert_eq!(d.timestamp, "2026-10-09T12:34:56.000Z"),
            other => panic!("expected Deliver, got {:?}", other),
        }
    }

    #[test]
    fn timezone_sign_and_magnitude() {
        // tz 0x4A: low nibble 0xA = sign bit + 2 tens, high nibble 4 units
        // → −24 quarter-hours = UTC−6; SCTS local 12:34:56 → 18:34:56Z
        let mut tpdu: Vec<u8> = vec![0x00, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0x00];
        tpdu.extend_from_slice(&[0x62, 0x01, 0x90, 0x21, 0x43, 0x65, 0x4A]);
        tpdu.push(0);
        let mut full = String::from("00");
        for b in &tpdu {
            full.push_str(&format!("{:02X}", b));
        }
        match decode_pdu(&full).unwrap() {
            PduKind::Deliver(d) => assert_eq!(d.timestamp, "2026-10-09T18:34:56.000Z"),
            other => panic!("expected Deliver, got {:?}", other),
        }
    }

    // ---- pack/unpack mirrors ----

    #[test]
    fn pack_hello_known_bytes() {
        assert_eq!(pack_septets(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]), vec![0xC8, 0x32, 0x9B, 0xFD, 0x06]);
        let back = unpack_septets(&[0xC8, 0x32, 0x9B, 0xFD, 0x06], 5);
        assert_eq!(back, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]);
    }

    #[test]
    fn semi_octets_roundtrip() {
        assert_eq!(pack_semi_octets(b"15551234567"), vec![0x51, 0x55, 0x21, 0x43, 0x65, 0xF7]);
        assert_eq!(unpack_semi_digits(&[0x51, 0x55, 0x21, 0x43, 0x65, 0xF7]).unwrap(), "15551234567");
        assert_eq!(unpack_semi_digits(&[0xFF]).unwrap(), "");
        assert!(unpack_semi_digits(&[0xAB]).is_none());
    }

    #[test]
    fn udl_counts_udh_septets() {
        // multi-segment UDL = 7 (UDH) + text septets; verified by decode
        let segs = split_septets(&"z".repeat(161), 5).unwrap(); // 161 → 2 segs (153 + 8)
        assert_eq!(segs.len(), 2);
        let pdus = encode_submit("+15551234567", &segs, 1, 0, true, 0x00).unwrap();
        let p = &pdus[0];
        let d = decode_submit_via_deliver(p);
        assert_eq!(d.text.len(), 153);
    }
}
