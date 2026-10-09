# cellmatik

Single-binary cellular gateway in Rust: a Quectel LTE modem (RM520N-GL or
SIM7600G-H) behind a LAN HTTP/JSON API carrying SMS, voice, and MMS.

One static binary, one TOML config, one SQLite file. No runtime
dependencies beyond libc.

## Features

**SMS — PDU end-to-end, not text mode**
- GSM-7 and UCS-2, concatenated messages first-class: outbound splits into
  per-segment submits (TS 23.40 concat UDH), inbound parts reassemble into
  one inbox row (staged, duplicate-safe, stale-flushed).
- Delivery tracking per segment: `+CMGS` assigns TP-MR, `+CDS` status
  reports roll up to a per-message status (`pending`/`submitted` detail →
  `delivered`/`failed`), with a validity-period sweep as the backstop for
  carriers that never send reports.
- Decoder is total over arbitrary bytes: no panics on malformed PDUs,
  bounded allocations, adversarial golden tests including live
  carrier-captured vectors.

**Voice** — WebSocket bidirectional g.711u audio (`/v1/calls/{id}/audio`),
  DTMF out via `AT+VTS`, detection on supported modems, ALSA device
  selection.

**MMS** — image + text outbound over the carrier MMSC, inbound retrieval
  over WAP push; the gateway manages its own data path (in-process DHCP +
  host routes on the wwan interface, an HTTP/1.1 client with proxy
  support, route assertion — no external networking tools).

**API security model**
- Bearer tokens (256-bit CSPRNG, SHA-256 at rest, shown once), 401 on
  everything but `/healthz`.
- Webhooks with `X-Webhook-Signature: sha256=…` HMAC, exponential backoff.
- SSE event stream (`/v1/events`) with `Last-Event-ID` replay from the
  inbox — reconnects never lose a message.
- Opaque 500s; no CORS; LAN-scoped by your firewall.

**Operations** — three-rung modem recovery ladder (AT probe → CFUN reboot
  → PWRKEY power cycle), boot-time CMGL import, nightly retention sweeps,
  systemd unit with `AmbientCapabilities`.

## Quickstart

```sh
cargo build --release                 # or: cargo build --release --no-default-features (no audio stack)
cp config.example.toml config.toml    # fill serial_path + modem_profile
./target/release/cellmatik --config config.toml token add ops   # prints a token once
./target/release/cellmatik --config config.toml
```

Systemd: `cellmatik.service` (needs `dialout` + `gpio` group membership;
see the unit file).

Send an SMS:

```sh
curl -s http://127.0.0.1:8080/v1/sms \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"to":"+15551234567","text":"hello","delivery_report":true}'
```

API surface: `/healthz`, `/v1/status`, `/v1/sms` (POST/GET, `GET {id}`),
`/v1/messages` (GET, `POST {id}/read`, `DELETE {id}`), `/v1/webhook`
(GET/PUT/DELETE), `/v1/events` (SSE), `/v1/calls` (POST/GET, `{id}`,
answer/hangup/dtmf, `audio` WebSocket), `/v1/mms` (POST/GET, `GET {id}`),
`/v1/media/{id}` (raw bytes).

## Deterministic end-to-end suite

`e2e_fake.py` (python3, stdlib only) builds a fake modem on a pty and runs
the full gateway against it: boot ladder, submit→`+CDS`→rollup,
multi-segment send, concatenated inbound assembly, SSE live+replay,
webhook HMAC, token auth, 422 shapes, read/delete.

```sh
cargo build --release
python3 e2e_fake.py ./target/release/cellmatik /tmp/e2e_work
```

All checks must pass; it is the regression gate for this repo.

## Hardware notes

- RM520N-GL: AT port, PDU mode, `CNMI=2,1,0,2,0` (verified by readback),
  `+QCCID` for ICCID, `+QNWINFO` for band.
- SIM7600G-H: DIP A on, `AT+DPTONE`/`AT+CPCMBANDWIDTH=1,1`, ECM
  provisioned at swap time.
- Status-report routing varies by carrier: some SMSCs never send
  `+CDS` even with TP-SRR set. Such messages stay `pending`/`submitted`
  and are failed by the validity sweep (`no_delivery_report`) — see
  `csmp_vp` and `stale_after_s`.

## License

MIT.
