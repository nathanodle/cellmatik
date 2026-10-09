//! MMS binary codec (spec §5 MMS codec) — the module is colloquially named
//! "wbxml" but MMS 1.x PDUs are NOT classic tag-token WBXML: per
//! OMA-MMS-ENC (WAP-209 / OMA-MMS-ENC-v1.3 §7) they are **WSP
//! field-value encoded** — each header is a short-integer field code
//! (0x80 | assigned number, Table 8) followed by a typed value
//! (short/long-integer, uintvar, text-string, encoded-string-value,
//! value-length-framed composites), and the body is a WSP multipart
//! container (WAP-230-WSP §8.5). There is no WBXML header (no
//! version/public-id/string-table bytes). Same primitive layer as the
//! SMS PDU codec: total functions, golden vectors, adversarial suite.
//!
//! CONTRACT:
//!  - Encode: M-Send.req (multipart: optional text/plain part + image part
//!    with name + Content-Type), M-NotifyResp.ind, M-Acknowledge.ind.
//!    Transaction IDs are caller-supplied ASCII tokens.
//!  - Decode: M-Notification.ind and M-Delivery.ind arrive wrapped in a
//!    WSP Push PDU (TID + type 0x06 + uintvar headers-length + headers
//!    [content-type first] + body) carried in the SMS user data —
//!    `decode_notification`/`decode_delivery_ind` parse the wrapper and
//!    require content-type `application/vnd.wap.mms-message` (short-int
//!    0xBE), stripping it bounds-checked. X-Mms-Content-Location is the
//!    retrieval URL — absolute or mmsc-relative, returned as-is.
//!    M-Retrieve.conf (multipart walk: every part's content-type, name,
//!    and bytes; first text/plain part becomes `text`) and M-Send.conf
//!    (X-Mms-Response-Status → Ok/Transient/Permanent/Unrecognized) are
//!    raw HTTP bodies — no WSP wrapper.
//!  - Response-status mapping (OMA-MMS-ENC §7.2.20): 0x80 Ok; 0xE0-0xFF
//!    transient class (0xE0 transient-failure, 0xE1 transient network
//!    problem) → Transient; 0xC0-0xDF permanent class → Permanent;
//!    legacy 1.0 codes 0x81 (unspecified) and 0x86 (network problem) →
//!    Transient, other 0x81-0x88 → Permanent; anything else
//!    Unrecognized(u8).
//!  - Media/content-type assigned numbers are wire-encoded as
//!    short-integers (0x80|n): text/plain 0x83, image/gif 0x9D,
//!    image/jpeg 0x9E, image/png 0xA0, multipart.mixed 0xA3,
//!    multipart.related 0xB3, mms-message 0xBE. Well-known parameter
//!    tokens likewise: Charset 0x81, Name 0x85, Filename 0x86, Start 0x8A.
//!  - **Security (spec §7)**: decode functions are total — malformed or
//!    hostile input (carrier-side, but also anything fetched over the
//!    bearer) returns `Err(WbxmlError::Malformed)`, never panics. Length
//!    fields (value-lengths, multipart part lengths, uintvars ≤ 5 octets)
//!    go through checked arithmetic; allocations are bounded by actual
//!    input size with a 10 MiB sanity ceiling and a 255-part cap; no
//!    unsafe. Encoded-string charsets are parsed but decoded as UTF-8
//!    (lossy) like python-messaging; documented limitation.



// ===== constants =====

/// Spec §7 bounded-decode ceiling.
const MAX_INPUT: usize = 10 * 1024 * 1024;
/// WSP uintvar maximum width (32-bit → 5 octets, WAP-230 §8.1.2).
const MAX_UINTVAR_OCTETS: usize = 5;
/// Multipart part-count ceiling (allocations stay input-bounded).
const MAX_PARTS: usize = 255;

// MMS field codes (OMA-MMS-ENC §7.3 Table 8, assigned numbers 1-24;
// wire form = 0x80 | n via `field()`).
const N_MESSAGE_TYPE: u8 = 0x0C;
const N_TRANSACTION_ID: u8 = 0x18;
const N_VERSION: u8 = 0x0D;
const N_MESSAGE_SIZE: u8 = 0x0E;
const N_EXPIRY: u8 = 0x08;
const N_FROM: u8 = 0x09;
const N_TO: u8 = 0x17;
const N_CC: u8 = 0x02;
const N_BCC: u8 = 0x01;
const N_MESSAGE_ID: u8 = 0x0B;
const N_RESPONSE_STATUS: u8 = 0x12;
const N_RESPONSE_TEXT: u8 = 0x13;
const N_STATUS: u8 = 0x15;
const N_CONTENT_LOCATION: u8 = 0x03;
const N_CONTENT_TYPE: u8 = 0x04;
const N_SUBJECT: u8 = 0x16;
const N_MESSAGE_CLASS: u8 = 0x0A;
const N_PRIORITY: u8 = 0x0F;
const N_DATE: u8 = 0x05;
const N_REPORT_ALLOWED: u8 = 0x11;

fn field(n: u8) -> u8 {
    0x80 | n
}

// Message-type values (OMA-MMS-ENC §7.2.14).
const MT_SEND_REQ: u8 = 0x80;
const MT_SEND_CONF: u8 = 0x81;
const MT_NOTIFICATION_IND: u8 = 0x82;
const MT_NOTIFYRESP_IND: u8 = 0x83;
const MT_RETRIEVE_CONF: u8 = 0x84;
const MT_ACKNOWLEDGE_IND: u8 = 0x85;
const MT_DELIVERY_IND: u8 = 0x86;

// MMS version 1.3 → short-integer of 0x13.
const VERSION_13: u8 = 0x93;

// WSP content-type assigned numbers (WAP-230 Table 40, 0-based).
const MEDIA_TEXT_PLAIN: u8 = 0x03;
const MEDIA_IMAGE_GIF: u8 = 0x1D;
const MEDIA_IMAGE_JPEG: u8 = 0x1E;
const MEDIA_IMAGE_PNG: u8 = 0x20;
const MEDIA_MULTIPART_MIXED: u8 = 0x23;
const MEDIA_MULTIPART_RELATED: u8 = 0x33;
const MEDIA_MMS_MESSAGE: u8 = 0x3E;

// WSP well-known parameter tokens (WAP-230 Table 38, short-int form).
const P_CHARSET: u8 = 0x81;
const P_NAME: u8 = 0x85;
const P_FILENAME: u8 = 0x86;
const P_START: u8 = 0x8A;

// WSP PDU types.
const WSP_PUSH: u8 = 0x06;

/// Content type of every MMS PDU.
pub const CT_MMS: &str = "application/vnd.wap.mms-message";

fn media_number(ct: &str) -> Option<u8> {
    Some(match ct {
        "text/plain" => MEDIA_TEXT_PLAIN,
        "image/gif" => MEDIA_IMAGE_GIF,
        "image/jpeg" => MEDIA_IMAGE_JPEG,
        "image/png" => MEDIA_IMAGE_PNG,
        "application/vnd.wap.multipart.mixed" => MEDIA_MULTIPART_MIXED,
        "application/vnd.wap.multipart.related" => MEDIA_MULTIPART_RELATED,
        "application/vnd.wap.mms-message" => MEDIA_MMS_MESSAGE,
        _ => return None,
    })
}

fn media_name(n: u8) -> Option<&'static str> {
    Some(match n {
        0x00 => "*/*",
        0x01 => "text/*",
        0x02 => "text/html",
        MEDIA_TEXT_PLAIN => "text/plain",
        0x06 => "text/x-vCalendar",
        0x07 => "text/x-vCard",
        0x0B => "multipart/*",
        0x0C => "multipart/mixed",
        0x0D => "multipart/form-data",
        0x0F => "multipart/alternative",
        0x10 => "application/*",
        0x11 => "application/java-vm",
        0x1C => "application/vnd.wap.wmlc",
        MEDIA_IMAGE_GIF => "image/gif",
        MEDIA_IMAGE_JPEG => "image/jpeg",
        0x1F => "image/tiff",
        MEDIA_IMAGE_PNG => "image/png",
        0x21 => "image/vnd.wap.wbmp",
        0x22 => "application/vnd.wap.multipart.*",
        MEDIA_MULTIPART_MIXED => "application/vnd.wap.multipart.mixed",
        0x27 => "application/xml",
        0x28 => "text/xml",
        0x29 => "application/vnd.wap.wbxml",
        0x2D => "text/vnd.wap.si",
        0x2F => "text/vnd.wap.sl",
        0x32 => "text/vnd.wap.co",
        MEDIA_MULTIPART_RELATED => "application/vnd.wap.multipart.related",
        0x37 => "application/pkcs7-mime",
        MEDIA_MMS_MESSAGE => CT_MMS,
        _ => return None,
    })
}

// ===== public types =====

#[derive(Debug, Clone, PartialEq)]
pub enum WbxmlError {
    Malformed(&'static str),
}

impl std::fmt::Display for WbxmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WbxmlError::Malformed(why) => write!(f, "wbxml malformed: {why}"),
        }
    }
}

impl std::error::Error for WbxmlError {}

/// Inbound picture notification (M-Notification.ind).
#[derive(Debug, Clone, PartialEq)]
pub struct NotificationInd {
    pub tx_id: String,
    /// Retrieval URL from X-Mms-Content-Location.
    pub content_location: String,
    pub message_size: Option<u64>,
    pub expiry_s: Option<u64>,
}

/// Result of a successful retrieval (M-Retrieve.conf).
#[derive(Debug, Clone, PartialEq)]
pub struct RetrieveConf {
    pub tx_id: String,
    pub from: Option<String>,
    /// Decoded text/plain part, if any.
    pub text: Option<String>,
    pub parts: Vec<MmsPart>,
}

/// One decoded multipart part.
#[derive(Debug, Clone, PartialEq)]
pub struct MmsPart {
    pub content_type: String,
    pub name: Option<String>,
    pub data: Vec<u8>,
}

/// M-Send.conf outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct SendConf {
    pub tx_id: String,
    pub status: MmsResponse,
    pub message_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmsResponse {
    Ok,
    /// Error-transient — worth retrying.
    Transient,
    /// Error-permanent — fail.
    Permanent,
    Unrecognized(u8),
}

// ===== bounds-checked reader =====

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd { b, i: 0 }
    }
    fn u8(&mut self) -> Result<u8, WbxmlError> {
        if self.i < self.b.len() {
            let v = self.b[self.i];
            self.i += 1;
            Ok(v)
        } else {
            Err(WbxmlError::Malformed("truncated"))
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WbxmlError> {
        match self.b.len().checked_sub(self.i) {
            Some(rem) if rem >= n => {
                let s = &self.b[self.i..self.i + n];
                self.i += n;
                Ok(s)
            }
            _ => Err(WbxmlError::Malformed("truncated")),
        }
    }
    fn rest(&self) -> &'a [u8] {
        &self.b[self.i.min(self.b.len())..]
    }
    fn done(&self) -> bool {
        self.i >= self.b.len()
    }

    /// WSP uintvar: ≤ 5 octets, high-bit continuation.
    fn uintvar(&mut self) -> Result<u64, WbxmlError> {
        let mut v: u64 = 0;
        for _k in 0..MAX_UINTVAR_OCTETS {
            let b = self.u8()?;
            v = v.checked_shl(7).ok_or(WbxmlError::Malformed("uintvar"))? | (b & 0x7F) as u64;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(WbxmlError::Malformed("uintvar"))
    }

    /// Integer-value = short-integer (MSB set) | long-integer.
    fn integer(&mut self) -> Result<u64, WbxmlError> {
        let b = self.peek().ok_or(WbxmlError::Malformed("truncated"))?;
        if b & 0x80 != 0 {
            self.i += 1;
            Ok((b & 0x7F) as u64)
        } else {
            // long-integer: short-length (≤ 30) then big-endian octets
            let n = self.u8()? as usize;
            if n > 8 {
                return Err(WbxmlError::Malformed("integer"));
            }
            let mut v: u64 = 0;
            for _ in 0..n {
                v = v.checked_shl(8).ok_or(WbxmlError::Malformed("integer"))? | self.u8()? as u64;
            }
            Ok(v)
        }
    }

    /// Value-length = short-length (0-30) | 0x1F + uintvar.
    fn value_length(&mut self) -> Result<usize, WbxmlError> {
        let b = self.peek().ok_or(WbxmlError::Malformed("truncated"))?;
        if b == 0x1F {
            self.i += 1;
            self.uintvar()?
                .try_into()
                .map_err(|_| WbxmlError::Malformed("value-length"))
        } else if b <= 30 {
            self.i += 1;
            Ok(b as usize)
        } else {
            Err(WbxmlError::Malformed("value-length"))
        }
    }

    /// Text-string: optional 0x7F quote, then bytes to NUL (lossy UTF-8).
    fn text_string(&mut self) -> Result<String, WbxmlError> {
        let first = self.u8()?;
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        let mut b = if first == 0x7F { self.u8()? } else { first };
        while b != 0x00 {
            bytes.push(b);
            b = self.u8()?;
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Encoded-string-value = Text-string | Value-length Char-set Text-string.
    /// The charset MIBenum is parsed and skipped (UTF-8 lossy decode).
    fn encoded_string(&mut self) -> Result<String, WbxmlError> {
        let b = self.peek().ok_or(WbxmlError::Malformed("truncated"))?;
        if b == 0x1F || b <= 30 {
            let len = self.value_length()?;
            let region = self.take(len)?;
            let mut sub = Rd::new(region);
            let _charset = sub.integer()?;
            if !sub.done() {
                sub.text_string()
            } else {
                Ok(String::new())
            }
        } else {
            self.text_string()
        }
    }
}

/// Decoded content-type value: media type + optional Name parameter.
struct CtValue {
    media: String,
    name: Option<String>,
}

impl<'a> Rd<'a> {
    /// Content-type-value = Constrained-media | Content-general-form.
    /// Constrained: single short-integer ≥ 0x80, or extension-media text.
    /// General: Value-length Media-type *(Parameter).
    fn content_type(&mut self) -> Result<CtValue, WbxmlError> {
        let b = self.peek().ok_or(WbxmlError::Malformed("truncated"))?;
        if b & 0x80 != 0 {
            // constrained-media: short-integer well-known code
            self.i += 1;
            let media = media_name(b & 0x7F).ok_or(WbxmlError::Malformed("media"))?;
            Ok(CtValue { media: media.to_string(), name: None })
        } else if b != 0x1F && b > 30 {
            // extension-media (NUL-terminated text) as constrained form
            let media = self.text_string()?;
            Ok(CtValue { media, name: None })
        } else {
            // general form: value-length + media + params
            let len = self.value_length()?;
            let region = self.take(len)?;
            let mut sub = Rd::new(region);
            let mb = sub.peek().ok_or(WbxmlError::Malformed("media"))?;
            let media = if mb & 0x80 != 0 {
                sub.i += 1;
                media_name(mb & 0x7F).ok_or(WbxmlError::Malformed("media"))?.to_string()
            } else {
                sub.text_string()?
            };
            let mut name = None;
            while !sub.done() {
                let tok = match sub.peek() {
                    Some(t) if t & 0x80 != 0 => t,
                    _ => break, // untyped/unknown parameter: skip the rest
                };
                sub.i += 1;
                match tok {
                    P_NAME | P_FILENAME | P_START => {
                        name = Some(sub.text_string()?);
                    }
                    P_CHARSET => {
                        let _ = sub.integer()?;
                    }
                    _ => break, // unknown well-known parameter: skip rest
                }
            }
            Ok(CtValue { media, name })
        }
    }
}

// ===== WSP push wrapper (SMS UD → MMS PDU body) =====

/// Strips the WSP Push wrapper: TID(1) + type 0x06 + uintvar
/// headers-length + headers (content-type first; headers-length counts
/// the content-type field too) → the MMS PDU body. Requires the
/// content-type to be `application/vnd.wap.mms-message`.
fn parse_wsp_push(bytes: &[u8]) -> Result<&[u8], WbxmlError> {
    let mut rd = Rd::new(bytes);
    let _tid = rd.u8()?;
    let pdu_type = rd.u8()?;
    if pdu_type != WSP_PUSH {
        return Err(WbxmlError::Malformed("push type"));
    }
    let headers_len: usize = rd
        .uintvar()?
        .try_into()
        .map_err(|_| WbxmlError::Malformed("headers-length"))?;
    let header_start = rd.i;
    let ct = rd.content_type()?;
    if ct.media != CT_MMS {
        return Err(WbxmlError::Malformed("content-type"));
    }
    let header_end = header_start
        .checked_add(headers_len)
        .ok_or(WbxmlError::Malformed("headers-length"))?;
    if header_end > bytes.len() || rd.i > header_end {
        return Err(WbxmlError::Malformed("headers-length"));
    }
    Ok(&bytes[header_end..])
}

// ===== MMS PDU field walk =====

/// One decoded MMS header.
enum F {
    MessageType(u8),
    TxId(String),
    MessageSize(u64),
    Expiry(u64),
    From(Option<String>),
    MessageId(String),
    ResponseStatus(u8),
    Status(u8),
    ContentLocation(String),
    ContentType(CtValue),
}

/// Walks MMS headers until the given stop field (Content-Type for PDUs
/// with a body) or end of input. Returns the fields in order plus the
/// reader positioned where the walk stopped (body start when stopped at
/// Content-Type).
fn walk_fields<'a>(rd: &mut Rd<'a>, stop_at_content_type: bool) -> Result<Vec<F>, WbxmlError> {
    let mut out = Vec::new();
    while !rd.done() {
        let code = rd.peek().ok_or(WbxmlError::Malformed("truncated"))?;
        if code < 0x80 {
            // Application-header: Token-text field name + Text-string value
            let _name = rd.text_string()?;
            let _value = rd.text_string()?;
            continue;
        }
        rd.i += 1; // consume the field code
        let f = match code {
            c if c == field(N_MESSAGE_TYPE) => F::MessageType(rd.u8()?),
            c if c == field(N_TRANSACTION_ID) => F::TxId(rd.text_string()?),
            c if c == field(N_VERSION) => {
                let _ = rd.integer()?;
                continue;
            }
            c if c == field(N_MESSAGE_SIZE) => F::MessageSize(rd.integer()?),
            c if c == field(N_EXPIRY) => {
                // Value-length (Absolute-token Date-value | Relative-token Delta-seconds)
                let len = rd.value_length()?;
                let region = rd.take(len)?;
                let mut sub = Rd::new(region);
                let tok = sub.u8()?;
                let secs = match tok {
                    0x80 => sub.integer()?, // absolute: unix seconds
                    0x81 => sub.integer()?, // relative: delta seconds (Integer-value)
                    _ => return Err(WbxmlError::Malformed("expiry")),
                };
                F::Expiry(secs)
            }
            c if c == field(N_FROM) => {
                // From-value = Value-length (Address-present-token Encoded-string | Insert-token)
                let len = rd.value_length()?;
                let region = rd.take(len)?;
                let mut sub = Rd::new(region);
                let tok = sub.u8()?;
                let addr = if tok == 0x80 {
                    Some(sub.encoded_string()?)
                } else if tok == 0x81 {
                    None
                } else {
                    return Err(WbxmlError::Malformed("from"));
                };
                F::From(addr)
            }
            c if c == field(N_TO) || c == field(N_CC) => {
                let _ = rd.encoded_string()?;
                continue;
            }
            c if c == field(N_BCC) => {
                // Bcc-value = Value-length (Address-present | Insert-token)
                let len = rd.value_length()?;
                let _ = rd.take(len)?;
                continue;
            }
            c if c == field(N_MESSAGE_ID) => F::MessageId(rd.text_string()?),
            c if c == field(N_RESPONSE_STATUS) => F::ResponseStatus(rd.u8()?),
            c if c == field(N_RESPONSE_TEXT) => {
                let _ = rd.encoded_string()?;
                continue;
            }
            c if c == field(N_STATUS) => F::Status(rd.u8()?),
            c if c == field(N_CONTENT_LOCATION) => F::ContentLocation(rd.text_string()?),
            c if c == field(N_SUBJECT) => {
                let _ = rd.encoded_string()?;
                continue;
            }
            c if c == field(N_MESSAGE_CLASS) => {
                // class-identifier byte (0x80-0x83) or token-text
                let b = rd.peek().ok_or(WbxmlError::Malformed("truncated"))?;
                if b & 0x80 != 0 {
                    rd.i += 1;
                } else {
                    let _ = rd.text_string()?;
                }
                continue;
            }
            c if c == field(N_PRIORITY) => {
                let _ = rd.u8()?;
                continue;
            }
            c if c == field(N_DATE) => {
                let _ = rd.integer()?;
                continue;
            }
            c if c == field(N_REPORT_ALLOWED) => {
                let _ = rd.u8()?;
                continue;
            }
            c if c == field(N_CONTENT_TYPE) => {
                // rd is positioned at the value (the field code is consumed):
                // read the content-type value; the multipart body follows it
                let ct = rd.content_type()?;
                out.push(F::ContentType(ct));
                if stop_at_content_type {
                    return Ok(out);
                }
                continue;
            }
            _ => return Err(WbxmlError::Malformed("field")),
        };
        out.push(f);
    }
    Ok(out)
}

fn field_find<'f>(fields: &'f [F], want_message_type: u8) -> Result<&'f [F], WbxmlError> {
    match fields.first() {
        Some(F::MessageType(mt)) if *mt == want_message_type => Ok(fields),
        _ => Err(WbxmlError::Malformed("message-type")),
    }
}

// ===== public API =====

/// M-Notification.ind decode.
pub fn decode_notification(bytes: &[u8]) -> Result<NotificationInd, WbxmlError> {
    if bytes.len() > MAX_INPUT {
        return Err(WbxmlError::Malformed("size"));
    }
    let body = parse_wsp_push(bytes)?;
    let mut rd = Rd::new(body);
    let fields = walk_fields(&mut rd, false)?;
    let fields = field_find(&fields, MT_NOTIFICATION_IND)?;
    let mut ind = NotificationInd {
        tx_id: String::new(),
        content_location: String::new(),
        message_size: None,
        expiry_s: None,
    };
    for f in fields.iter().skip(1) {
        match f {
            F::TxId(t) => ind.tx_id = t.clone(),
            F::MessageSize(s) => ind.message_size = Some(*s),
            F::Expiry(s) => ind.expiry_s = Some(*s),
            F::ContentLocation(u) => ind.content_location = u.clone(),
            F::From(_) | F::ContentType(_) | F::Status(_) => {}
            _ => return Err(WbxmlError::Malformed("field")),
        }
    }
    if ind.tx_id.is_empty() || ind.content_location.is_empty() {
        return Err(WbxmlError::Malformed("notification"));
    }
    Ok(ind)
}

/// M-Retrieve.conf decode (multipart walk).
pub fn decode_retrieve_conf(bytes: &[u8]) -> Result<RetrieveConf, WbxmlError> {
    if bytes.len() > MAX_INPUT {
        return Err(WbxmlError::Malformed("size"));
    }
    let mut rd = Rd::new(bytes);
    let fields = walk_fields(&mut rd, true)?;
    let fields = field_find(&fields, MT_RETRIEVE_CONF)?;
    let mut conf = RetrieveConf {
        tx_id: String::new(),
        from: None,
        text: None,
        parts: Vec::new(),
    };
    for f in fields.iter().skip(1) {
        match f {
            F::TxId(t) => conf.tx_id = t.clone(),
            F::From(a) => conf.from = a.clone(),
            F::ContentType(ct) => {
                if ct.media != "application/vnd.wap.multipart.mixed"
                    && ct.media != "application/vnd.wap.multipart.related"
                {
                    return Err(WbxmlError::Malformed("multipart"));
                }
            }
            _ => return Err(WbxmlError::Malformed("field")),
        }
    }
    if conf.tx_id.is_empty() {
        return Err(WbxmlError::Malformed("transaction-id"));
    }
    // the reader stopped right after the Content-Type value: multipart body
    conf.parts = parse_multipart(rd.rest())?;
    if let Some(text_part) = conf.parts.iter().find(|p| p.content_type == "text/plain") {
        conf.text = Some(String::from_utf8_lossy(&text_part.data).into_owned());
    }
    Ok(conf)
}

/// WSP multipart container: uintvar count; per part uintvar headers-len,
/// uintvar data-len, headers, data.
fn parse_multipart(body: &[u8]) -> Result<Vec<MmsPart>, WbxmlError> {
    let mut rd = Rd::new(body);
    let count: usize = rd
        .uintvar()?
        .try_into()
        .map_err(|_| WbxmlError::Malformed("parts"))?;
    if count > MAX_PARTS {
        return Err(WbxmlError::Malformed("parts"));
    }
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        let headers_len: usize = rd
            .uintvar()?
            .try_into()
            .map_err(|_| WbxmlError::Malformed("part"))?;
        let data_len: usize = rd
            .uintvar()?
            .try_into()
            .map_err(|_| WbxmlError::Malformed("part"))?;
        let headers = rd.take(headers_len)?;
        let data = rd.take(data_len)?;
        let mut hrd = Rd::new(headers);
        let ct = hrd.content_type()?;
        // remaining part headers (Content-ID, Content-Disposition, …) sit
        // inside the already-bounded headers region: skipped
        parts.push(MmsPart {
            content_type: ct.media,
            name: ct.name,
            data: data.to_vec(),
        });
    }
    Ok(parts)
}

/// M-Send.conf decode.
pub fn decode_send_conf(bytes: &[u8]) -> Result<SendConf, WbxmlError> {
    if bytes.len() > MAX_INPUT {
        return Err(WbxmlError::Malformed("size"));
    }
    let mut rd = Rd::new(bytes);
    let fields = walk_fields(&mut rd, false)?;
    let fields = field_find(&fields, MT_SEND_CONF)?;
    let mut conf = SendConf {
        tx_id: String::new(),
        status: MmsResponse::Unrecognized(0),
        message_id: None,
    };
    for f in fields.iter().skip(1) {
        match f {
            F::TxId(t) => conf.tx_id = t.clone(),
            F::ResponseStatus(s) => conf.status = map_response(*s),
            F::MessageId(m) => conf.message_id = Some(m.clone()),
            F::MessageSize(_) | F::ContentType(_) => {}
            _ => return Err(WbxmlError::Malformed("field")),
        }
    }
    if conf.tx_id.is_empty() {
        return Err(WbxmlError::Malformed("transaction-id"));
    }
    Ok(conf)
}

/// OMA-MMS-ENC §7.2.20 (see module doc for the transient/permanent split).
fn map_response(status: u8) -> MmsResponse {
    match status {
        0x80 => MmsResponse::Ok,
        0xE0..=0xFF => MmsResponse::Transient,
        0xC0..=0xDF => MmsResponse::Permanent,
        0x81 | 0x86 => MmsResponse::Transient, // legacy: unspecified, network problem
        0x82..=0x88 => MmsResponse::Permanent,  // legacy: format corrupt … unsupported
        _ => MmsResponse::Unrecognized(status),
    }
}

/// M-Delivery.ind decode (used only when mms_delivery_ack is on):
/// message-id + status byte (retrieved|rejected|expired...).
pub fn decode_delivery_ind(bytes: &[u8]) -> Result<(String, u8), WbxmlError> {
    if bytes.len() > MAX_INPUT {
        return Err(WbxmlError::Malformed("size"));
    }
    let body = parse_wsp_push(bytes)?;
    let mut rd = Rd::new(body);
    let fields = walk_fields(&mut rd, false)?;
    let fields = field_find(&fields, MT_DELIVERY_IND)?;
    let mut message_id = String::new();
    let mut status = 0u8;
    for f in fields.iter().skip(1) {
        match f {
            F::MessageId(m) => message_id = m.clone(),
            F::Status(s) => status = *s,
            F::TxId(_) | F::From(_) | F::MessageSize(_) => {}
            _ => return Err(WbxmlError::Malformed("field")),
        }
    }
    if message_id.is_empty() {
        return Err(WbxmlError::Malformed("message-id"));
    }
    Ok((message_id, status))
}

// ===== encoders (byte-push helpers) =====

fn push_uintvar(out: &mut Vec<u8>, v: u64) {
    let mut groups = Vec::with_capacity(5);
    let mut x = v;
    groups.push((x & 0x7F) as u8);
    x >>= 7;
    while x > 0 {
        groups.push(0x80 | (x & 0x7F) as u8);
        x >>= 7;
    }
    groups.reverse();
    out.extend_from_slice(&groups);
}

fn push_value_length(out: &mut Vec<u8>, len: usize) {
    if len <= 30 {
        out.push(len as u8);
    } else {
        out.push(0x1F);
        push_uintvar(out, len as u64);
    }
}

fn push_text_string(out: &mut Vec<u8>, s: &str) -> Result<(), WbxmlError> {
    for b in s.bytes() {
        if b < 0x20 || b == 0x7F {
            return Err(WbxmlError::Malformed("text"));
        }
        out.push(b);
    }
    out.push(0x00);
    Ok(())
}

/// ASCII token for transaction ids / names (no separators, no NUL).
fn push_token(out: &mut Vec<u8>, s: &str, why: &'static str) -> Result<(), WbxmlError> {
    for b in s.bytes() {
        if b < 0x21 || b > 0x7E {
            return Err(WbxmlError::Malformed(why));
        }
        out.push(b);
    }
    Ok(())
}

/// M-NotifyResp.ind encode (status: 128 = Ok).
pub fn encode_notify_resp(tx_id: &str, status: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.push(field(N_MESSAGE_TYPE));
    out.push(MT_NOTIFYRESP_IND);
    out.push(field(N_TRANSACTION_ID));
    // caller-supplied token; tolerate with lossy ASCII push
    let _ = push_token(&mut out, tx_id, "tx-id");
    out.push(0x00);
    out.push(field(N_VERSION));
    out.push(VERSION_13);
    out.push(field(N_RESPONSE_STATUS));
    out.push(status);
    out
}

/// M-Acknowledge.ind encode.
pub fn encode_acknowledge(tx_id: &str, from: &str, status: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.push(field(N_MESSAGE_TYPE));
    out.push(MT_ACKNOWLEDGE_IND);
    out.push(field(N_TRANSACTION_ID));
    let _ = push_token(&mut out, tx_id, "tx-id");
    out.push(0x00);
    out.push(field(N_VERSION));
    out.push(VERSION_13);
    // From-value: Value-length + Address-present-token (0x80) + address
    let mut addr = Vec::with_capacity(from.len() + 2);
    addr.push(0x80);
    let _ = push_text_string(&mut addr, from);
    out.push(field(N_FROM));
    push_value_length(&mut out, addr.len());
    out.extend_from_slice(&addr);
    // Report-Allowed boolean (128 = Yes → sender gets a delivery report)
    out.push(field(N_REPORT_ALLOWED));
    out.push(status);
    out
}

/// M-Send.req encode: multipart with optional text part + exactly one
/// image part (`image` = (name, content_type, bytes)).
pub fn encode_send_req(
    to: &str,
    tx_id: &str,
    text: Option<&str>,
    image: Option<(&str, &str, &[u8])>,
) -> Result<Vec<u8>, WbxmlError> {
    if text.is_none() && image.is_none() {
        return Err(WbxmlError::Malformed("no parts"));
    }
    if to.is_empty() {
        return Err(WbxmlError::Malformed("to"));
    }
    let mut out = Vec::with_capacity(96);
    out.push(field(N_MESSAGE_TYPE));
    out.push(MT_SEND_REQ);
    out.push(field(N_TRANSACTION_ID));
    push_token(&mut out, tx_id, "tx-id")?;
    out.push(0x00);
    out.push(field(N_VERSION));
    out.push(VERSION_13);
    out.push(field(N_TO));
    push_text_string(&mut out, to)?;
    out.push(field(N_MESSAGE_CLASS));
    out.push(0x80); // Personal
    out.push(field(N_PRIORITY));
    out.push(0x81); // Normal
    out.push(field(N_CONTENT_TYPE));
    out.push(0x80 | MEDIA_MULTIPART_MIXED);

    // multipart body
    let n_parts = text.is_some() as u8 + image.is_some() as u8;
    push_uintvar(&mut out, n_parts as u64);
    if let Some(t) = text {
        push_uintvar(&mut out, 1); // headers_len: content-type only
        let data = t.as_bytes();
        push_uintvar(&mut out, data.len() as u64);
        out.push(0x80 | MEDIA_TEXT_PLAIN);
        out.extend_from_slice(data);
    }
    if let Some((name, ct, data)) = image {
        // part content-type: general form with Name parameter
        let mut hdr = Vec::with_capacity(24);
        let mut ctv = Vec::with_capacity(16);
        match media_number(ct) {
            Some(n) => ctv.push(0x80 | n),
            None => push_text_string(&mut ctv, ct)?, // extension-media
        }
        let param_len = 1 + name.len() + 1; // token + name + NUL
        push_value_length(&mut hdr, ctv.len() + param_len);
        hdr.extend_from_slice(&ctv);
        hdr.push(P_NAME);
        push_token(&mut hdr, name, "name")?;
        hdr.push(0x00);
        push_uintvar(&mut out, hdr.len() as u64);
        push_uintvar(&mut out, data.len() as u64);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(data);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02X}", b)).collect()
    }

    // ---- golden: canonical M-Notification.ind (WSP-wrapped) ----

    #[test]
    fn notification_golden() {
        // WSP: TID 07, Push 06, headers-len 01 (content-type 0xBE only).
        // Body: 8C 82 (notification-ind), 98 'A' 00 (tx), 8D 93 (v1.3),
        // 8E 9F (size 31, short-integer), 88 04 81 02 04 D2 (relative
        // expiry 1234 s: token + long-integer short-length 2 + 04 D2),
        // 83 'U''R''L' 00 (content-location).
        let bytes: Vec<u8> = [
            0x07, 0x06, 0x01, 0xBE, 0x8C, 0x82, 0x98, b'A', 0x00, 0x8D, 0x93,
            0x8E, 0x9F, 0x88, 0x04, 0x81, 0x02, 0x04, 0xD2, 0x83, b'U', b'R', b'L', 0x00,
        ]
        .to_vec();
        let n = decode_notification(&bytes).unwrap();
        assert_eq!(n.tx_id, "A");
        assert_eq!(n.content_location, "URL");
        assert_eq!(n.message_size, Some(31));
        assert_eq!(n.expiry_s, Some(1234));
        // byte-exact prefix assertions against the hand-built vector
        assert_eq!(hex(&bytes[4..6]), "8C82");
    }

    #[test]
    fn notification_absolute_expiry_and_big_size() {
        // absolute expiry: token 0x80 + long-integer date 0x405F7E00
        // (= 1_080_000_000 unix seconds); size 300 = long-integer 02 01 2C
        let mut bytes: Vec<u8> = vec![
            0x07, 0x06, 0x01, 0xBE, 0x8C, 0x82, 0x98, b'B', 0x00, 0x8D, 0x93,
            0x8E, 0x02, 0x01, 0x2C, 0x88, 0x06, 0x80, 0x04, 0x40, 0x5F, 0x7E, 0x00,
        ];
        bytes.extend_from_slice(&[0x83, b'M', 0x00]);
        let n = decode_notification(&bytes).unwrap();
        assert_eq!(n.message_size, Some(300));
        assert_eq!(n.expiry_s, Some(1_080_000_000));
    }

    #[test]
    fn notification_real_capture_shape() {
        // carrier-style wrapper: headers region = content-type + an
        // X-Wap-Application-Id-ish app header inside headers-length
        let mut body: Vec<u8> = vec![
            0x8C, 0x82, 0x98, b'2', 0x00, 0x8D, 0x93, 0x8E, 0xC0, 0x88, 0x04, 0x81, 0x02, 0x04, 0xD2,
        ];
        body.extend_from_slice(b"\x83http://mmsc.example.com/mms/123\x00");
        let mut wrapper: Vec<u8> = vec![0x0B, 0x06];
        // headers: BE (content-type) + app-header "x" "y" → length 1 + 3 + 2 = 6
        let headers: Vec<u8> = [0xBEu8, b'x', 0x00, b'y', 0x00].to_vec();
        wrapper.push(headers.len() as u8);
        wrapper.extend_from_slice(&headers);
        wrapper.extend_from_slice(&body);
        let n = decode_notification(&wrapper).unwrap();
        assert_eq!(n.tx_id, "2");
        assert_eq!(n.content_location, "http://mmsc.example.com/mms/123");
        assert_eq!(n.message_size, Some(64));
    }

    // ---- golden: M-Delivery.ind ----

    #[test]
    fn delivery_ind_golden() {
        let bytes: Vec<u8> = [
            0x07, 0x06, 0x01, 0xBE, // WSP wrapper
            0x8C, 0x86, // m-delivery-ind
            0x98, b'D', 0x00, // tx
            0x8D, 0x93, // version
            0x8B, b'm', 0x00, // message-id "m"
            0x95, 0x81, // status: retrieved
        ]
        .to_vec();
        let (id, status) = decode_delivery_ind(&bytes).unwrap();
        assert_eq!(id, "m");
        assert_eq!(status, 0x81);
    }

    // ---- golden: M-Send.conf + response mapping ----

    #[test]
    fn send_conf_golden_and_mapping() {
        let ok: Vec<u8> = [
            0x8C, 0x81, 0x98, b'C', 0x00, 0x8D, 0x93, 0x92, 0x80, 0x8B, b'm', b's', b'g', 0x00,
        ]
        .to_vec();
        let c = decode_send_conf(&ok).unwrap();
        assert_eq!(c.tx_id, "C");
        assert_eq!(c.status, MmsResponse::Ok);
        assert_eq!(c.message_id.as_deref(), Some("msg"));
        // status classes
        let mk = |s: u8| -> Vec<u8> {
            vec![0x8C, 0x81, 0x98, b'C', 0x00, 0x8D, 0x93, 0x92, s]
        };
        assert_eq!(decode_send_conf(&mk(0xE0)).unwrap().status, MmsResponse::Transient);
        assert_eq!(decode_send_conf(&mk(0xE1)).unwrap().status, MmsResponse::Transient);
        assert_eq!(decode_send_conf(&mk(0xC0)).unwrap().status, MmsResponse::Permanent);
        assert_eq!(decode_send_conf(&mk(0xC5)).unwrap().status, MmsResponse::Permanent);
        assert_eq!(decode_send_conf(&mk(0x81)).unwrap().status, MmsResponse::Transient);
        assert_eq!(decode_send_conf(&mk(0x86)).unwrap().status, MmsResponse::Transient);
        assert_eq!(decode_send_conf(&mk(0x83)).unwrap().status, MmsResponse::Permanent);
        assert_eq!(decode_send_conf(&mk(0x88)).unwrap().status, MmsResponse::Permanent);
        assert_eq!(
            decode_send_conf(&mk(0x99)).unwrap().status,
            MmsResponse::Unrecognized(0x99)
        );
    }

    // ---- golden: encoders ----

    #[test]
    fn encode_notify_resp_golden() {
        let out = encode_notify_resp("N", 128);
        let expect: Vec<u8> = [0x8C, 0x83, 0x98, b'N', 0x00, 0x8D, 0x93, 0x92, 0x80].to_vec();
        assert_eq!(out, expect);
    }

    #[test]
    fn encode_acknowledge_golden() {
        let out = encode_acknowledge("K", "+123", 128);
        let expect: Vec<u8> = [
            0x8C, 0x85, 0x98, b'K', 0x00, 0x8D, 0x93, // headers
            0x89, 0x06, 0x80, b'+', b'1', b'2', b'3', 0x00, // From
            0x91, 0x80, // Report-Allowed: yes
        ]
        .to_vec();
        assert_eq!(out, expect);
    }

    #[test]
    fn encode_send_req_golden() {
        let out = encode_send_req(
            "+15551234567",
            "T1",
            Some("hi"),
            Some(("a.jpg", "image/jpeg", &[0xFF, 0xD8, 0xFF, 0xD9])),
        )
        .unwrap();
        let mut expect: Vec<u8> = vec![
            0x8C, 0x80, // m-send-req
            0x98, b'T', b'1', 0x00, // tx
            0x8D, 0x93, // v1.3
            0x97, // To
        ];
        expect.extend_from_slice(b"+15551234567\x00");
        expect.extend_from_slice(&[0x8A, 0x80, 0x8F, 0x81, 0x84, 0xA3]); // class, priority, ct
        expect.extend_from_slice(&[0x02]); // count
        expect.extend_from_slice(&[0x01, 0x02, 0x83, b'h', b'i']); // text part
        expect.extend_from_slice(&[0x09, 0x04, 0x08, 0x9E, 0x85, b'a', b'.', b'j', b'p', b'g', 0x00, 0xFF, 0xD8, 0xFF, 0xD9]); // image part
        assert_eq!(out, expect);
    }

    // ---- roundtrips ----

    #[test]
    fn send_req_roundtrips_through_retrieve_conf() {
        let img: Vec<u8> = (0..64u8).collect();
        let out = encode_send_req("+15551234567", "TX9", Some("héllo {}"), Some(("pic.png", "image/png", &img))).unwrap();
        // multipart body = everything after the content-type field value
        let body_idx = out
            .windows(2)
            .position(|w| w == [0x84, 0xA3])
            .expect("content-type field")
            + 2;
        let body = &out[body_idx..];
        // wrap as m-retrieve-conf
        let mut r: Vec<u8> = vec![0x8C, 0x84, 0x98, b'T', b'X', b'9', 0x00, 0x8D, 0x93];
        let mut from = Vec::new();
        from.push(0x80);
        from.extend_from_slice(b"+15551234567\x00");
        r.push(0x89);
        r.push(from.len() as u8);
        r.extend_from_slice(&from);
        r.extend_from_slice(&[0x84, 0xA3]);
        r.extend_from_slice(body);
        let conf = decode_retrieve_conf(&r).unwrap();
        assert_eq!(conf.tx_id, "TX9");
        assert_eq!(conf.from.as_deref(), Some("+15551234567"));
        assert_eq!(conf.text.as_deref(), Some("héllo {}"));
        assert_eq!(conf.parts.len(), 2);
        assert_eq!(conf.parts[0].content_type, "text/plain");
        assert_eq!(conf.parts[1].content_type, "image/png");
        assert_eq!(conf.parts[1].name.as_deref(), Some("pic.png"));
        assert_eq!(conf.parts[1].data, img);
    }

    #[test]
    fn image_only_and_text_only_roundtrip() {
        let img = [0x00u8, 0x01, 0x02];
        let out = encode_send_req("+15551234567", "I1", None, Some(("x", "image/jpeg", &img))).unwrap();
        assert_eq!(out[0], 0x8C);
        let text = encode_send_req("+15551234567", "T2", Some("words"), None).unwrap();
        // both decodable as multipart via a retrieve wrapper
        let body_of = |enc: &[u8]| -> Vec<u8> {
            let idx = enc.windows(2).position(|w| w == [0x84, 0xA3]).unwrap() + 2;
            let mut r: Vec<u8> = vec![0x8C, 0x84, 0x98, b'R', 0x00, 0x8D, 0x93, 0x84, 0xA3];
            r.extend_from_slice(&enc[idx..]);
            r
        };
        let c1 = decode_retrieve_conf(&body_of(&out)).unwrap();
        assert_eq!(c1.parts.len(), 1);
        assert!(c1.text.is_none());
        assert_eq!(c1.parts[0].data, img.to_vec());
        let c2 = decode_retrieve_conf(&body_of(&text)).unwrap();
        assert_eq!(c2.text.as_deref(), Some("words"));
        assert_eq!(c2.parts.len(), 1);
    }

    #[test]
    fn extension_media_content_type_roundtrip() {
        // unknown content type string → extension-media → decoded back
        let out = encode_send_req("+15551234567", "E1", None, Some(("w", "image/webp", &[1, 2]))).unwrap();
        let idx = out.windows(2).position(|w| w == [0x84, 0xA3]).unwrap() + 2;
        let mut r: Vec<u8> = vec![0x8C, 0x84, 0x98, b'R', 0x00, 0x8D, 0x93, 0x84, 0xA3];
        r.extend_from_slice(&out[idx..]);
        let conf = decode_retrieve_conf(&r).unwrap();
        assert_eq!(conf.parts[0].content_type, "image/webp");
        assert_eq!(conf.parts[0].name.as_deref(), Some("w"));
    }

    #[test]
    fn charset_prefixed_from_decodes() {
        // From with charset-prefixed encoded-string (MIBenum 106 = utf-8 → 0xEA)
        let mut r: Vec<u8> = vec![0x8C, 0x84, 0x98, b'C', 0x00, 0x8D, 0x93];
        let inner: Vec<u8> = [0x80u8, 0x05, 0xEA, b'+', b'1', b'2', 0x00].to_vec();
        r.push(0x89);
        r.push(inner.len() as u8);
        r.extend_from_slice(&inner);
        r.extend_from_slice(&[0x84, 0xA3, 0x00]); // ct multipart.mixed, zero parts
        let conf = decode_retrieve_conf(&r).unwrap();
        assert_eq!(conf.from.as_deref(), Some("+12"));
        assert!(conf.parts.is_empty());
    }

    // ---- adversarial: total, never panic ----

    #[test]
    fn adversarial_all_prefixes() {
        let good: Vec<u8> = [
            0x07, 0x06, 0x01, 0xBE, 0x8C, 0x82, 0x98, b'A', 0x00, 0x8D, 0x93,
            0x8E, 0x1F, 0x88, 0x03, 0x81, 0x89, 0x52, 0x83, b'U', 0x00,
        ]
        .to_vec();
        for n in 0..good.len() {
            let _ = decode_notification(&good[..n]); // must not panic
            let _ = decode_delivery_ind(&good[..n]);
        }
    }

    #[test]
    fn adversarial_shapes() {
        assert_eq!(decode_notification(&[]).unwrap_err(), WbxmlError::Malformed("truncated"));
        // not a push
        assert_eq!(decode_notification(&[0x07, 0x04]).unwrap_err(), WbxmlError::Malformed("push type"));
        // wrong content type (text/plain 0x83)
        let wrong_ct: Vec<u8> = [0x07u8, 0x06, 0x01, 0x83].to_vec();
        assert_eq!(decode_notification(&wrong_ct).unwrap_err(), WbxmlError::Malformed("content-type"));
        // headers-length past end
        let bad_hl: Vec<u8> = [0x07u8, 0x06, 0x7F, 0xBE].to_vec();
        assert!(matches!(
            decode_notification(&bad_hl),
            Err(WbxmlError::Malformed(_))
        ));
        // headers-length uintvar with 6 continuation octets
        let mut long_uv: Vec<u8> = vec![0x07, 0x06];
        long_uv.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);
        long_uv.push(0xBE);
        assert_eq!(decode_notification(&long_uv).unwrap_err(), WbxmlError::Malformed("uintvar"));
        // unterminated text-string
        let unterm: Vec<u8> = [0x07u8, 0x06, 0x01, 0xBE, 0x8C, 0x82, 0x98, b'A'].to_vec();
        assert!(decode_notification(&unterm).is_err());
        // wrong message-type in wrapper body (m-send-conf 0x81)
        let wrong_mt: Vec<u8> = [0x07u8, 0x06, 0x01, 0xBE, 0x8C, 0x81, 0x98, b'A', 0x00].to_vec();
        assert_eq!(decode_notification(&wrong_mt).unwrap_err(), WbxmlError::Malformed("message-type"));
        // missing content-location → Err
        let no_url: Vec<u8> = [0x07u8, 0x06, 0x01, 0xBE, 0x8C, 0x82, 0x98, b'A', 0x00, 0x8D, 0x93].to_vec();
        assert_eq!(decode_notification(&no_url).unwrap_err(), WbxmlError::Malformed("notification"));
        // 10 MiB ceiling
        let huge = vec![0u8; MAX_INPUT + 1];
        assert_eq!(decode_notification(&huge).unwrap_err(), WbxmlError::Malformed("size"));
        // unknown well-known field code 0x9D (Sender-Visibility is 0x94; 0x9D unmapped)
        let unknown_field: Vec<u8> = [0x07u8, 0x06, 0x01, 0xBE, 0x8C, 0x82, 0x98, b'A', 0x00, 0x9D, 0x80].to_vec();
        assert_eq!(decode_notification(&unknown_field).unwrap_err(), WbxmlError::Malformed("field"));
    }

    #[test]
    fn adversarial_multipart() {
        // count 255 with no part bytes
        let mut r: Vec<u8> = vec![0x8C, 0x84, 0x98, b'R', 0x00, 0x8D, 0x93, 0x84, 0xA3, 0x81, 0x7F];
        assert_eq!(decode_retrieve_conf(&r).unwrap_err(), WbxmlError::Malformed("truncated"));
        // part data_len beyond the buffer
        r = vec![
            0x8C, 0x84, 0x98, b'R', 0x00, 0x8D, 0x93, 0x84, 0xA3, 0x01, 0x01, 0x7F, 0x83, b'x',
        ];
        assert!(decode_retrieve_conf(&r).is_err());
        // part headers_len beyond
        r = vec![0x8C, 0x84, 0x98, b'R', 0x00, 0x8D, 0x93, 0x84, 0xA3, 0x01, 0x7F, 0x01, 0x83];
        assert!(decode_retrieve_conf(&r).is_err());
        // count above the cap (256)
        r = vec![0x8C, 0x84, 0x98, b'R', 0x00, 0x8D, 0x93, 0x84, 0xA3, 0x82, 0x00];
        assert_eq!(decode_retrieve_conf(&r).unwrap_err(), WbxmlError::Malformed("parts"));
        // zero parts is fine
        r = vec![0x8C, 0x84, 0x98, b'R', 0x00, 0x8D, 0x93, 0x84, 0xA3, 0x00];
        assert!(decode_retrieve_conf(&r).unwrap().parts.is_empty());
    }

    #[test]
    fn adversarial_send_conf_and_delivery() {
        // empty
        assert!(decode_send_conf(&[]).is_err());
        // truncated mid-value
        assert!(decode_send_conf(&[0x8C, 0x81, 0x98]).is_err());
        // value-length claiming more than present (Response-Text region)
        let bad: Vec<u8> = [0x8Cu8, 0x81, 0x98, b'C', 0x00, 0x8D, 0x93, 0x93, 0x7F].to_vec();
        assert!(decode_send_conf(&bad).is_err());
        // delivery-ind with empty message-id
        let d: Vec<u8> = [0x07u8, 0x06, 0x01, 0xBE, 0x8C, 0x86, 0x98, b'D', 0x00, 0x8D, 0x93, 0x95, 0x81].to_vec();
        assert_eq!(decode_delivery_ind(&d).unwrap_err(), WbxmlError::Malformed("message-id"));
    }

    #[test]
    fn encoder_rejects_bad_tokens() {
        assert_eq!(
            encode_send_req("+15551234567", "T\u{1}1", None, Some(("a", "image/png", &[1]))).unwrap_err(),
            WbxmlError::Malformed("tx-id")
        );
        assert_eq!(
            encode_send_req("+15551234567", "T1", None, Some(("a b", "image/png", &[1]))).unwrap_err(),
            WbxmlError::Malformed("name")
        );
        assert_eq!(
            encode_send_req("+15551234567", "T1", None, None).unwrap_err(),
            WbxmlError::Malformed("no parts")
        );
        assert_eq!(
            encode_send_req("", "T1", Some("x"), None).unwrap_err(),
            WbxmlError::Malformed("to")
        );
    }
}
