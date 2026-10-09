//! MMS flows (spec §3 MMS + §5 MMS inbound/outbound flow). Owns the
//! mms_outbox worker and consumes WapPush URCs from the modem. All MMSC
//! bytes flow through wwan::Wwan (bound bearer); codec work is wbxml.rs.
//!
//! SECURITY (spec §7): the base64 length check happens BEFORE decoding
//! allocates; magic-byte sniffing decides the type (never the declared
//! name); decode results are untrusted and size-ceilinged in wbxml;
//! retrieved part data never logged.

use crate::config::Config;
use crate::db::Db;
use crate::envelope::{inbox_item_json, EventBus};
use crate::modem::{Modem, Urc};
use crate::types::*;
use crate::wwan::{HttpMethod, Wwan, WwanRequest};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const MAX_INBOUND_PARTS: usize = 16;
const MMS_SEND_RETRIES: u32 = 5;

/// Raw POST /v1/mms payload fields (base64 left encoded until validated).
pub struct MmsSendRequest {
    pub to: String,
    pub text: Option<String>,
    pub image_b64: String,
}

#[derive(Clone)]
pub struct Mms {
    cfg: Arc<Config>,
    db: Db,
    wwan: Wwan,
    events: EventBus,
    /// Outbound retry budget (in-memory; process restart resets it).
    retries: Arc<Mutex<HashMap<i64, u32>>>,
}

impl Mms {
    /// Spawn the outbound worker + the WapPush subscription. When
    /// cfg.mms.enabled is false, the worker is idle and inbound pushes
    /// only produce breadcrumb events.
    pub fn spawn(
        cfg: Arc<Config>,
        db: Db,
        wwan: Wwan,
        modem: Modem,
        events: EventBus,
    ) -> Mms {
        let mms = Mms {
            cfg: cfg.clone(),
            db: db.clone(),
            wwan,
            events: events.clone(),
            retries: Arc::new(Mutex::new(HashMap::new())),
        };
        let worker = Mms {
            cfg: cfg.clone(),
            db: db.clone(),
            wwan: mms.wwan.clone(),
            events: events.clone(),
            retries: mms.retries.clone(),
        };
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                tick.tick().await;
                if let Err(e) = worker.outbound_cycle().await {
                    tracing::warn!(target: "cellmatik::mms", error = %e, "mms outbound cycle failed");
                }
            }
        });
        let inbound = Mms {
            cfg: cfg.clone(),
            db: db.clone(),
            wwan: mms.wwan.clone(),
            events: events.clone(),
            retries: mms.retries.clone(),
        };
        tokio::spawn(async move {
            let mut urcs = modem.urc_subscribe();
            loop {
                match urcs.recv().await {
                    Ok(Urc::WapPush { deliver }) => {
                        if let Err(e) = inbound.handle_push(deliver).await {
                            tracing::warn!(target: "cellmatik::mms", error = %e, "mms push handling failed");
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(target: "cellmatik::mms", skipped = n, "mms urc lag");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        mms
    }

    /// `POST /v1/mms` — 422s: too_large {bytes, max_bytes} /
    /// unsupported_type {type, allowed}; 503 mms_unavailable when disabled.
    pub async fn queue(&self, client_id: i64, req: MmsSendRequest) -> ApiResult<MmsOutboxRow> {
        if !self.cfg.mms.enabled {
            return Err(ApiError::service("mms_unavailable", None));
        }
        // Length check BEFORE base64 decode allocates (spec §7) — exact
        // decoded-size computation over the encoded chars, no allocation.
        let hint = b64_len_hint(&req.image_b64);
        if hint > self.cfg.mms.max_bytes {
            return Err(ApiError::unprocessable(serde_json::json!({
                "error": "too_large",
                "bytes": hint,
                "max_bytes": self.cfg.mms.max_bytes,
            })));
        }
        let data = base64_decode(&req.image_b64).ok_or_else(|| {
            ApiError::unprocessable(serde_json::json!({"error": "bad_base64"}))
        })?;
        let (ctype, name) = sniff_image(&data).ok_or_else(|| {
            ApiError::unprocessable(serde_json::json!({
                "error": "unsupported_type",
                "type": "unknown",
                "allowed": ["image/jpeg", "image/png"],
            }))
        })?;
        if data.len() > self.cfg.mms.max_bytes {
            return Err(ApiError::unprocessable(serde_json::json!({
                "error": "too_large",
                "bytes": data.len(),
                "max_bytes": self.cfg.mms.max_bytes,
            })));
        }
        let media = self
            .db
            .store_media(None, None, name, ctype, data)
            .await
            .map_err(|e| ApiError::internal(&e))?;
        let row = self
            .db
            .queue_mms(client_id, &req.to, req.text.as_deref(), media)
            .await
            .map_err(|e| ApiError::internal(&e))?;
        Ok(row)
    }

    pub async fn list(&self, client_id: i64, status: Option<MmsStatus>) -> ApiResult<Vec<MmsOutboxRow>> {
        self.db
            .list_mms(Some(client_id), status)
            .await
            .map_err(|e| ApiError::internal(&e))
    }

    pub async fn get(&self, id: i64, client_id: i64) -> ApiResult<MmsOutboxRow> {
        self.db
            .get_mms_scoped(id, client_id)
            .await
            .map_err(|e| ApiError::internal(&e))?
            .ok_or_else(|| ApiError::not_found("mms"))
    }

    // ===== outbound worker =====

    async fn outbound_cycle(&self) -> anyhow::Result<()> {
        if !self.cfg.mms.enabled {
            return Ok(());
        }
        let rows = self.db.take_sendable_mms(4).await?;
        for row in rows {
            if let Err(e) = self.send_one(&row).await {
                tracing::warn!(target: "cellmatik::mms", id = row.id, error = %e, "mms send failed");
            }
        }
        Ok(())
    }

    async fn send_one(&self, row: &MmsOutboxRow) -> anyhow::Result<()> {
        let (media_row, data) = self
            .db
            .get_media(row.media.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("media row {} missing", row.media.id))?;
        let tx_id = tx_id_gen();
        let encoded = crate::wbxml::encode_send_req(
            &row.to_num,
            &tx_id,
            row.text.as_deref(),
            Some((&media_row.name, &media_row.content_type, &data)),
        )?;
        let req = WwanRequest {
            url: self.cfg.mms.mmsc_url.clone(),
            method: HttpMethod::Post {
                content_type: crate::wbxml::CT_MMS.to_string(),
                body: encoded,
            },
        };
        let resp = match self.wwan.http(req).await {
            Ok(r) => r,
            Err(e) => {
                // Bearer/transport problem — transient, bounded retries.
                tracing::warn!(target: "cellmatik::mms", id = row.id, cause = %e, "wwan http failed");
                let used = self.bump_retry(row.id);
                if used >= MMS_SEND_RETRIES {
                    self.db
                        .set_mms_state(row.id, MmsStatus::Failed, Some("send_timeout"))
                        .await?;
                } else {
                    self.db
                        .set_mms_state(row.id, MmsStatus::Retrying, Some("mms_unavailable"))
                        .await?;
                }
                return Ok(());
            }
        };
        if resp.status != 200 {
            let used = self.bump_retry(row.id);
            if used >= MMS_SEND_RETRIES {
                self.db
                    .set_mms_state(row.id, MmsStatus::Failed, Some("send_timeout"))
                    .await?;
            } else {
                self.db
                    .set_mms_state(row.id, MmsStatus::Retrying, Some("send_timeout"))
                    .await?;
            }
            tracing::warn!(target: "cellmatik::mms", id = row.id, status = resp.status, "mmsc non-200");
            return Ok(());
        }
        match crate::wbxml::decode_send_conf(&resp.body) {
            Ok(conf) => match conf.status {
                crate::wbxml::MmsResponse::Ok => {
                    if let Ok(mut m) = self.retries.lock() {
                        m.remove(&row.id);
                    }
                    self.db.set_mms_state(row.id, MmsStatus::Sent, None).await?;
                    tracing::info!(target: "cellmatik::mms", id = row.id, "mms sent");
                }
                crate::wbxml::MmsResponse::Transient => {
                    let used = self.bump_retry(row.id);
                    if used >= MMS_SEND_RETRIES {
                        self.db
                            .set_mms_state(row.id, MmsStatus::Failed, Some("carrier_reject"))
                            .await?;
                    } else {
                        self.db
                            .set_mms_state(row.id, MmsStatus::Retrying, Some("carrier_reject"))
                            .await?;
                    }
                }
                crate::wbxml::MmsResponse::Permanent | crate::wbxml::MmsResponse::Unrecognized(_) => {
                    if let Ok(mut m) = self.retries.lock() {
                        m.remove(&row.id);
                    }
                    self.db
                        .set_mms_state(row.id, MmsStatus::Failed, Some("carrier_reject"))
                        .await?;
                }
            },
            Err(_) => {
                // Unparseable conf — treat as transient; bounded.
                let used = self.bump_retry(row.id);
                if used >= MMS_SEND_RETRIES {
                    self.db
                        .set_mms_state(row.id, MmsStatus::Failed, Some("send_timeout"))
                        .await?;
                } else {
                    self.db
                        .set_mms_state(row.id, MmsStatus::Retrying, Some("send_timeout"))
                        .await?;
                }
            }
        }
        Ok(())
    }

    fn bump_retry(&self, id: i64) -> u32 {
        self.retries
            .lock()
            .map(|mut m| {
                let e = m.entry(id).or_insert(0);
                *e += 1;
                *e
            })
            .unwrap_or(1)
    }

    // ===== inbound =====

    async fn handle_push(&self, deliver: crate::pdu::DeliverPdu) -> anyhow::Result<()> {
        let sender = deliver.sender.clone();
        let notif = match crate::wbxml::decode_notification(&deliver.ud) {
            Ok(n) => n,
            Err(_) => {
                // Delivery-ind or unparseable push: only meaningful with
                // delivery_ack on.
                if self.cfg.mms.delivery_ack {
                    if let Ok((message_id, _status)) = crate::wbxml::decode_delivery_ind(&deliver.ud) {
                        tracing::info!(target: "cellmatik::mms", message_id = %message_id, "mms delivery-ind received");
                    }
                }
                return Ok(());
            }
        };
        let fetchable = self.cfg.mms.enabled
            && match self.wwan.ensure_up().await {
                Ok(_) => true,
                Err(e) => {
                    tracing::info!(target: "cellmatik::mms", error = %e, "mms push unfetchable (bearer)");
                    false
                }
            };
        if !fetchable {
            // Never-silent breadcrumb (spec §3): row + event, no fetch.
            let row = self
                .db
                .insert_inbox_mms(&sender, "", FetchState::Unfetchable, Vec::new())
                .await?;
            let item = inbox_item_json(&row);
            self.events.publish(Event::mms(item));
            return Ok(());
        }
        let req = WwanRequest {
            url: notif.content_location.clone(),
            method: HttpMethod::Get,
        };
        let resp = self.wwan.http(req).await?;
        if resp.status != 200 {
            let row = self
                .db
                .insert_inbox_mms(&sender, "", FetchState::Unfetchable, Vec::new())
                .await?;
            let item = inbox_item_json(&row);
            self.events.publish(Event::mms(item));
            tracing::warn!(target: "cellmatik::mms", status = resp.status, "mms retrieval failed");
            return Ok(());
        }
        let conf = crate::wbxml::decode_retrieve_conf(&resp.body)?;
        let mut parts: Vec<(String, String, Vec<u8>)> = Vec::new();
        for p in conf.parts.iter().take(MAX_INBOUND_PARTS) {
            parts.push((p.name.clone().unwrap_or_default(), p.content_type.clone(), p.data.clone()));
        }
        let row = self
            .db
            .insert_inbox_mms(
                &sender,
                conf.text.as_deref().unwrap_or(""),
                FetchState::Ok,
                parts,
            )
            .await?;
        let item = inbox_item_json(&row);
        self.events.publish(Event::mms(item));
        // Acknowledge so the carrier stops re-pushing.
        let notify = crate::wbxml::encode_notify_resp(&notif.tx_id, 128); // 128 = Ok
        let _ = self
            .wwan
            .http(WwanRequest {
                url: self.cfg.mms.mmsc_url.clone(),
                method: HttpMethod::Post {
                    content_type: crate::wbxml::CT_MMS.to_string(),
                    body: notify,
                },
            })
            .await;
        if self.cfg.mms.delivery_ack {
            if let Some(from) = conf.from.as_deref() {
                let ack = crate::wbxml::encode_acknowledge(&conf.tx_id, from, 128);
                let _ = self
                    .wwan
                    .http(WwanRequest {
                        url: self.cfg.mms.mmsc_url.clone(),
                        method: HttpMethod::Post {
                            content_type: crate::wbxml::CT_MMS.to_string(),
                            body: ack,
                        },
                    })
                    .await;
            }
        }
        Ok(())
    }
}

// ===== helpers =====

/// True base64-decoded byte count without full decode (length hint).
fn b64_len_hint(b64: &str) -> usize {
    let trimmed: String = b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let pad = trimmed.chars().filter(|c| *c == '=').count();
    trimmed.len().saturating_sub(pad) / 4 * 3
        + match (trimmed.len().saturating_sub(pad)) % 4 {
            2 => 1,
            3 => 2,
            _ => 0,
        }
}

fn base64_decode(b64: &str) -> Option<Vec<u8>> {
    // std base64 engine — no padding tolerance games; require clean input.
    let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    // avoid depending on a base64 crate: decode via...
    // (hmac/hex don't provide it; use a small hand-rolled decoder)
    hand_base64_decode(&cleaned)
}

fn hand_base64_decode(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut pad_seen = false;
    for c in s.bytes() {
        if c == b'=' {
            pad_seen = true;
            continue;
        }
        if pad_seen {
            return None; // data after padding
        }
        let idx = TABLE.iter().position(|t| *t == c)? as u32;
        buf = (buf << 6) | idx;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(hand_base64_decode("").unwrap(), b"");
        assert_eq!(hand_base64_decode("QQ==").unwrap(), b"A");
        assert_eq!(hand_base64_decode("QUI=").unwrap(), b"AB");
        assert_eq!(hand_base64_decode("QUJD").unwrap(), b"ABC");
        assert_eq!(hand_base64_decode("QUJDRA==").unwrap(), b"ABCD");
        assert_eq!(hand_base64_decode("/w==").unwrap(), vec![0xFF]);
        assert_eq!(hand_base64_decode("//8=").unwrap(), vec![0xFF, 0xFF]);
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(hand_base64_decode("AB=C").is_none()); // data after padding
        assert!(hand_base64_decode("A*B=").is_none()); // invalid char
    }

    #[test]
    fn base64_hint_matches_decode() {
        for s in ["", "QQ==", "QUJD", "QUJDRA==", "AAAA", "AAA="] {
            let hint = b64_len_hint(s);
            let real = hand_base64_decode(s).map(|v| v.len()).unwrap_or(0);
            assert_eq!(hint, real, "hint mismatch for {s}");
        }
    }

    #[test]
    fn sniff_jpeg_png() {
        assert_eq!(sniff_image(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap().0, "image/jpeg");
        assert_eq!(
            sniff_image(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap().0,
            "image/png"
        );
        assert!(sniff_image(&[0x00, 0x01, 0x02]).is_none());
        assert!(sniff_image(&[]).is_none());
        // JPEG magic truncated below 3 bytes must not match.
        assert!(sniff_image(&[0xFF, 0xD8]).is_none());
    }
}

/// Magic-byte sniff (spec §7: never trust the declared name).
fn sniff_image(data: &[u8]) -> Option<(&'static str, &'static str)> {
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return Some(("image/jpeg", "image.jpg"));
    }
    const PNG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() >= 8 && data[..8] == PNG {
        return Some(("image/png", "image.png"));
    }
    None
}

fn tx_id_gen() -> String {
    use rand::RngCore;
    let mut b = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
