# cellmatik HTTP API

One binary, one port: SMS, voice, and MMS over LAN HTTP/JSON plus SSE and
one WebSocket. Every endpoint is versioned under `/v1`. This document is
the complete surface; the executable contract is `e2e_fake.py` (45 checks)
plus the unit suite — if code and this file disagree, that is a bug.

- Base URL: `http://<host>:8080` (config `listen`)
- Content type: `application/json` for requests and responses
- Request body limit: 16 MiB
- No CORS headers are ever emitted — this API is for LAN clients, not browsers

## Authentication

Every route except `GET /healthz` requires a bearer token:

```
Authorization: Bearer <64-hex-token>
```

Tokens are created with the CLI (never via the API), stored as SHA-256
hashes, and printed exactly once:

```sh
cellmatik --config /etc/cellmatik/config.toml token add my-client   # prints token
cellmatik --config /etc/cellmatik/config.toml token list            # names + ids only
cellmatik --config /etc/cellmatik/config.toml token revoke my-client
```

Bad, missing, or revoked tokens return `401`:

```json
{"error": "unauthorized"}
```

Tokens ride only in the `Authorization` header — never query strings. The
SSE stream and the audio WebSocket authenticate on the initial HTTP
request (the WS upgrade), so browser-native `EventSource` needs a proxy
that injects the header.

## Conventions

**Timestamps** — UTC, RFC 3339 with milliseconds, always 24 characters:
`2026-01-01T12:00:00.000Z`.

**Phone numbers** — strict E.164: `+` followed by 10–15 digits
(`+15551234567`). The API does not silently repair malformed numbers.

**Envelopes** — list endpoints return named arrays: `{"items": [...]}`
(outbox, calls, MMS) and `{"messages": [...]}` (unified inbox).

**Errors** — every non-2xx carries a body with an `error` string; the two
flavors of 422 come from different layers:

| Status | Body | When |
|---|---|---|
| 400 | plain text (framework) | request body is not valid JSON |
| 401 | `{"error":"unauthorized"}` | missing/bad/revoked token |
| 403 | `{"error":"forbidden"}` | acting on another client's call |
| 404 | `{"error":"not_found","what":"sms\|message\|call\|mms\|media\|webhook"}` | unknown id |
| 405 | (axum default) | wrong method for the path |
| 409 | `{"error":"already_ended"}` | answer/hangup/dtmf on an ended call |
| 422 | plain text (framework) | JSON that does not fit the request struct — missing or wrongly-typed fields |
| 422 | `{"error":"malformed","field":"to"}` etc. (JSON) | semantic validation — bad E.164, invalid filter value, too-long text, unsupported media type, invalid webhook URL |
| 500 | `{"error":"internal"}` | opaque; details in the service log |
| 503 | `{"error":"queue_full"}` / `{"error":"mms_unavailable"}` | backpressure / feature off |

Outbox rows are scoped to the token's client: one client never sees
another client's sends. The inbox, calls list, and media are shared.

**Outbox status model** — stored status is only `pending`, `delivered`, or
`failed`. While pending, a derived `detail` field says where the message
is: `queued` (not yet handed to the modem), `retrying` (transient failure,
will resubmit), or `submitted` (modem accepted it, TP-MR assigned,
awaiting delivery confirmation). `check_after_s` is the earliest the
status could plausibly change — poll after that. On `failed`, `error`
holds the reason (`no_delivery_report` when the validity period expired
without a `+CDS`, `submit_timeout`, `expired`, or a numeric `+CMS ERROR`
code) and `retryable` says whether a re-send can succeed.

---

## Health & status

### GET /healthz

Unauthenticated liveness. `{"status":"ok","uptime_s":123}`.

### GET /v1/status

Snapshot of modem, SIM, network, and derived capability.

```json
{
  "modem":  {"model": "SIMCOM_SIM7600G-H", "fw": "SIM7600G_V2.0.2", "state": "ready"},
  "sim":    {"state": "ready", "iccid": "89014104334641310985", "msisdn": "+15739992523"},
  "network": {"registered": true, "operator": "AT&T", "rat": "lte", "band": "B2", "csq": 15},
  "sms":    {"delivery_capable": "unknown", "last_cds": null},
  "voice":  {"supported": true},
  "mms":    {"enabled": false, "bearer": "disabled"}
}
```

- `modem.state`: `probing` | `ready` | `recovering` | `unresponsive`
- `delivery_capable` is learned, not configured: `ok` once a `+CDS`
  arrives or inbound messages flow, `blocked` when ≥3 recent sends were
  submitted but nothing delivers and no inbound arrives (self-sends to
  the SIM's own number never count toward `blocked`), `unknown` before
  evidence. `last_cds` is the most recent delivery-report timestamp.
- `band` is the radio's current band token (`B2`, `n41`, ...); `csq` is
  0–31 RSSI (99 = unknown).

---

## SMS

### POST /v1/sms

Queue an outbound SMS. Returns `202` immediately with the full outbox
item — submission to the modem happens asynchronously.

Request:

| Field | Type | Notes |
|---|---|---|
| `to` | string | required, E.164 |
| `text` | string | required; GSM-7 and UCS-2 both fine |
| `delivery_report` | bool | optional; defaults to `default_delivery_report` config |

```sh
curl -s http://127.0.0.1:8080/v1/sms \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"to":"+15551234567","text":"hello","delivery_report":true}'
```

Response `202` (the item shape; identical on all outbox reads):

```json
{
  "id": 1,
  "to": "+15551234567",
  "text": "hello",
  "status": "pending",
  "detail": "queued",
  "check_after_s": 2,
  "segments": 1,
  "attempts": 0,
  "created_at": "2026-01-01T12:00:00.000Z",
  "submitted_at": null,
  "delivered_at": null,
  "error": null
}
```

Long texts split into concatenated segments (TS 23.040 UDH); `segments` is
the count. Errors: `422 {"error":"malformed","field":"to"}` for a bad
number; `422 {"error":"too_long","chars":N,"max_chars":M,"segments_needed":K,"max_segments":J}`
when the text needs more segments than `max_segments` allows;
`503 {"error":"queue_full"}` when `queue_limit` pending messages exist.

### GET /v1/sms

List this client's outbox. Optional `?status=pending|delivered|failed`
filter; anything else is `422 {"error":"invalid_status"}`.

```json
{"items": [ ...outbox items... ]}
```

### GET /v1/sms/{id}

One outbox item, or `404 {"error":"not_found","what":"sms"}`.

---

## Unified inbox

SMS and MMS land in one inbox.

### GET /v1/messages

| Query | Type | Notes |
|---|---|---|
| `since` | int | only messages with id > since |
| `unread` | bool | only unread (default false) |
| `limit` | int | default 200, clamped 1–1000 |

```json
{"messages": [{
  "id": 7,
  "from": "+15551234567",
  "channel": "sms",
  "text": "hello back",
  "media": [],
  "received_at": "2026-01-01T12:00:01.000Z",
  "read": false
}]}
```

`channel` is `sms` or `mms`. MMS rows carry `media` entries
(`{id, name, type, bytes}`) and — when retrieval did not fully succeed —
a `fetch` field (`ok` | `unfetchable`). Concatenated inbound parts are
reassembled server-side: 3 segments arrive as one row, never three.

### POST /v1/messages/{id}/read

Mark read. `200` with the updated item (same shape as the list entry).

### DELETE /v1/messages/{id}

`204` on success, `404` if already gone.

---

## Webhooks

One webhook per client. On every event (same payloads as SSE) the gateway
POSTs the JSON body to your URL with
`X-Webhook-Signature: sha256=<hex>` — an HMAC-SHA256 of the raw body
using a per-webhook secret. Verify the signature before trusting the body.

### PUT /v1/webhook

`{"url": "http://192.168.1.20:9000/hook"}` — must be `http://` or
`https://`, max 512 chars. Response:

```json
{"url": "http://192.168.1.20:9000/hook", "secret": "<64-hex>"}
```

The secret is shown once, on this response only. Re-PUT to rotate.

### GET /v1/webhook

```json
{"url": "...", "failing": false, "last_error": null, "last_ok": "2026-01-01T12:00:00.000Z"}
```

### DELETE /v1/webhook

`204`. Always.

Delivery: 5 attempts with 10→160 s exponential backoff on non-2xx or
transport failure; after the 5th the webhook is marked `failing: true`
(`last_error` says why) until a later success clears it. Webhooks keep
firing while the modem is down — they only need the LAN.

---

## SSE event stream

### GET /v1/events

Server-Sent Events. Each event's `data` is
`{"type": "<kind>", "data": { ... }}`; inbox events also carry an SSE
`id:` equal to the inbox row id.

| `type` | `data` | has `id:` |
|---|---|---|
| `message` | inbox item (SMS) | yes |
| `mms` | inbox item (MMS) | yes |
| `call_incoming` | call item | no |
| `call_state` | call item | no |
| `dtmf` | `{"call_id": N, "digits": "123"}` | no |
| `modem_state` | `{"state": "recovering"}` / `{"wwan":"route_violation","detail":"..."}` | no |

Reconnect with `Last-Event-ID: <last inbox id>` and the gateway replays
every message/mms row newer than that id (up to 500) before the live
stream — reconnects never lose a message. Call, DTMF, and modem events
are live-only. A `keep-alive` comment arrives every `heartbeat_s`.

---

## Voice

### POST /v1/calls

Originate an outbound call.

| Field | Type | Notes |
|---|---|---|
| `to` | string | E.164 |
| `audio` | bool | attach audio (default true) |
| `hangup_after_s` | int | auto-hangup, optional |

`202` with the call item (same shape everywhere):

```json
{
  "id": 3,
  "direction": "out",
  "to": "+15551234567",
  "status": "dialing",
  "cause": null,
  "owner": "my-client",
  "audio": true,
  "hangup_after_s": null,
  "created_at": "2026-01-01T12:00:00.000Z",
  "active_at": null,
  "ended_at": null
}
```

Inbound rows key the remote as `from` instead of `to`. `status`:
`incoming` | `dialing` | `active` | `ended`; `cause` carries the
disconnect reason once ended.

Calls are owned by the client that created or answered them: answer,
hangup, dtmf, and audio on another client's call return
`403 {"error":"forbidden"}`; on an ended call, `409 {"error":"already_ended"}`.

### GET /v1/calls

`?status=incoming|dialing|active|ended` (else `422 invalid_status`) and
`?since=<timestamp>`.

### GET /v1/calls/{id}

One call item or `404 {"error":"not_found","what":"call"}`.

### POST /v1/calls/{id}/answer

Answer an inbound call. `200` with the updated item.

### POST /v1/calls/{id}/hangup

End any call. `200` with the updated item.

### POST /v1/calls/{id}/dtmf

`{"digits": "123#"}` — out-of-band DTMF via `AT+VTS`. `204`.

### GET /v1/calls/{id}/audio

WebSocket upgrade (bearer auth on the upgrade request). Bidirectional
binary frames of raw g.711u (µ-law) 8 kHz audio — send frames to play
audio into the call, receive frames to hear the remote party.

---

## MMS

Requires `mms.enabled = true` in config; otherwise every MMS route
returns `503 {"error":"mms_unavailable"}`.

### POST /v1/mms

| Field | Type | Notes |
|---|---|---|
| `to` | string | E.164 |
| `text` | string | optional |
| `image_b64` | string | required, base64 image bytes |

`422 {"error":"unsupported_type","type":"...","allowed":["image/jpeg","image/png"]}`
for a disallowed content type. `202` with the MMS item:

```json
{
  "id": 1,
  "to": "+15551234567",
  "text": "look",
  "media": [{"name": "cam.jpg", "type": "image/jpeg", "bytes": 10240}],
  "status": "pending",
  "detail": "queued",
  "check_after_s": 2,
  "created_at": "2026-01-01T12:00:00.000Z",
  "sent_at": null,
  "error": null
}
```

`status`: `pending` | `sending` | `retrying` | `sent` | `delivered` |
`failed`. On `failed`, `retryable` is true for `mms_unavailable` /
`send_timeout`.

### GET /v1/mms

`?status=pending|sending|retrying|sent|delivered|failed`.

### GET /v1/mms/{id}

One MMS item or `404 {"error":"not_found","what":"mms"}`.

### GET /v1/media/{id}

Raw media bytes with the stored `Content-Type` — an image body, not JSON.
`404 {"error":"not_found","what":"media"}` for unknown ids. Inbox MMS
rows reference these ids from their `media` array.

---

## Configuration knobs that surface in the API

| Key | Default | Effect on API behavior |
|---|---|---|
| `listen` | `0.0.0.0:8080` | bind address |
| `queue_limit` | 32 | pending outbox cap → `503 queue_full` |
| `max_segments` | 10 | segment cap → `422 too_long` |
| `default_delivery_report` | true | when a send omits `delivery_report` |
| `csmp_vp` | 167 | validity period (167 = 24 h) before `no_delivery_report` |
| `stale_after_s` | 120 | pending-without-submit age that flips detail to `retrying` |
| `heartbeat_s` | 20 | SSE keep-alive interval |
| `webhook_timeout_s` | 5 | per-attempt webhook HTTP timeout |

See `config.example.toml` for the full list with comments.
