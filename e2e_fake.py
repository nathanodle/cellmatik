#!/usr/bin/env python3
"""Cellmatik fake-modem pty e2e (deterministic, no real modem).

Covers: boot ladder, submit→PDU→CDS→rollup, multi-segment submit, inbound
concat (CMTI→CMGR→staging→one inbox row), SSE live + replay, webhook HMAC,
token auth, 422 shapes, delete.

Usage: python3 e2e_fake.py <cellmatik-binary> <workdir>
Exits 0 on pass, 1 on fail; prints each assertion.
"""

import base64
import hashlib
import hmac
import http.server
import json
import os
import pty
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

PORT = 18099
OWN_NUMBER = "+15551234567"
SMS_DEST = "+15559876543"

# GSM 03.38 default alphabet, septets 0..127 (ESC at 0x1B, per the impl)
GSM7 = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM7_INDEX = {c: i for i, c in enumerate(GSM7)}

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))
    return bool(cond)


def semi_digits(digits):
    """Semi-octet phone encoding, F-padded."""
    d = digits + ("F" if len(digits) % 2 else "")
    return bytes.fromhex("".join(d[i + 1] + d[i] for i in range(0, len(d), 2)))


def bits_lsb(value, n):
    """n bits of value, least-significant first."""
    return "".join(str((value >> k) & 1) for k in range(n))


def pack_bits(bits):
    """Stream bits (index j) → octets: bit j lives at position j%8 of octet
    j//8 (GSM 03.40 §9.2.3.24 LSB-first packing)."""
    out = bytearray((len(bits) + 7) // 8)
    for j, b in enumerate(bits):
        if b == "1":
            out[j // 8] |= 1 << (j % 8)
    return bytes(out)


def self_check_packing():
    # golden vector, matches pdu.rs pack_hello_known_bytes
    got = pack_bits("".join(bits_lsb(s, 7) for s in (0x48, 0x65, 0x6C, 0x6C, 0x6F)))
    assert got == bytes([0xC8, 0x32, 0x9B, 0xFD, 0x06]), f"pack self-check failed: {got.hex()}"


def septets_of(text):
    return [GSM7_INDEX[c] for c in text]


def deliver_pdu(sender, text, ref=0, idx=1, total=1):
    """SMS-DELIVER hex (GSM-7, optional 8-bit concat UDH)."""
    digits = sender.lstrip("+")
    toa = 0x91 if sender.startswith("+") else 0x81
    scts = bytes.fromhex("62019021436569")  # 2026-10-09 12:34:56 local, tz 0x69 = UTC−4
    # user-data bitstream: UDH octets (8 bits each, LSB-first), zero-padded
    # to a septet boundary, then the message septets (7 bits each)
    stream = ""
    if total > 1:
        # TS 23.040 §9.2.3.24.1: IED = [ref, MAX, SEQ]
        udh = bytes([0x05, 0x00, 0x03, ref, total, idx])
        stream = "".join(bits_lsb(b, 8) for b in udh)
        while len(stream) % 7:
            stream += "0"
    stream += "".join(bits_lsb(s, 7) for s in septets_of(text))
    ud = pack_bits(stream)
    udl = len(stream) // 7
    fo = 0x40 if total > 1 else 0x00
    tpdu = bytes([fo, len(digits), toa]) + semi_digits(digits) + bytes([0x00, 0x00]) + scts + bytes([udl]) + ud
    return ("00" + tpdu.hex().upper(), len(tpdu))


def cds_pdu(mr, dest_digits):
    """SMS-STATUS-REPORT (delivered) referencing TP-MR."""
    toa = 0x91
    scts = bytes.fromhex("62019021436500")
    dt = bytes.fromhex("62019021437500")  # 12:34:57
    tpdu = bytes([0x02, mr, len(dest_digits), toa]) + semi_digits(dest_digits) + scts + dt + bytes([0x00])
    return ("00" + tpdu.hex().upper(), len(tpdu))


class FakeModem(threading.Thread):
    """Owns the pty master; speaks AT to the gateway under test."""

    def __init__(self):
        super().__init__(daemon=True)
        self.master, self.slave_fd = pty.openpty()
        # NOTE: the slave fd is intentionally KEPT OPEN — a pty master
        # EIOs while no slave fd exists, which would kill our reader the
        # moment before the gateway opens the port. The gateway opens its
        # own fd (TIOCEXCL only blocks future opens, ours stays valid), and
        # its close/reopen cycles keep working through our held fd.
        self.slave_path = os.ttyname(self.slave_fd)
        self.buf = b""
        self.lock = threading.Lock()
        self.stop = False
        # observability
        self.cmgs_count = 0
        self.submitted_pdus = []
        self.cds_sent = 0
        # scripted CMGR responses: index → pdu hex
        self.staged = {}
        # boot-time stored messages served by CMGL (index, pdu hex)
        self.stored_cmgl = []
        self.cmgd_indices = []
        self.staged_cond = threading.Condition(self.lock)

    def run(self):
        while not self.stop:
            r, _, _ = select.select([self.master], [], [], 0.1)
            if not r:
                continue
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                time.sleep(0.05)  # transient EIO (all gateway fds closed) — retry
                continue
            if not chunk:
                time.sleep(0.05)
                continue
            self.buf += chunk
            self.pump()

    def pump(self):
        # PDU submit arrives hex + 0x1a without newline
        if b"\x1a" in self.buf:
            raw, _, rest = self.buf.partition(b"\x1a")
            self.buf = rest
            self.on_pdu_submit(raw)
            if self.buf:
                self.pump()
            return
        while b"\r" in self.buf or b"\n" in self.buf:
            raw, _, rest = re_partition(self.buf)
            self.buf = rest
            line = raw.decode("ascii", "ignore").strip()
            if line:
                self.on_line(line)

    def send(self, data: bytes):
        os.write(self.master, data)

    def ok(self):
        self.send(b"\r\nOK\r\n")

    def on_line(self, line):
        if line.startswith("AT+CMGS="):
            self.pdu_pending = True  # next raw frame is the PDU
            self.send(b"\r\n> ")     # prompt is a raw '>' byte
            return
        if line.startswith("AT+CMGR="):
            idx = int(line.split("=")[1])
            with self.lock:
                pdu = self.staged.pop(idx, None)
            if pdu:
                self.send(f"\r\n+CMGR: 0,,{len(pdu) // 2 - 1}\r\n{pdu}\r\n".encode())
            self.ok()
            return
        if line.startswith("AT+CMGD="):
            try:
                self.cmgd_indices.append(int(line.split("=")[1]))
            except ValueError:
                pass
            self.ok()
            return
        if line.startswith("AT+CMGL"):
            # one stored deliver from a previous session: exercises the
            # boot import (decode → inbox row → delete by CMGL index)
            with self.lock:
                stored = self.stored_cmgl[0] if self.stored_cmgl else None
            if stored:
                idx, pdu = stored
                self.send(f"\r\n+CMGL: {idx},1,,{len(pdu) // 2 - 1}\r\n{pdu}\r\n".encode())
                self.stored_cmgl.pop(0)
            self.ok()
            return
        if line.startswith("AT+QCFG"):
            self.send(b'\r\n+QCFG: "usbnet",3,1\r\n')
            self.ok()
            return
        if line.startswith("AT+CNMI?"):
            self.send(b"\r\n+CNMI: 2,1,0,2,0\r\n")
            self.ok()
            return
        if line.startswith("AT+CPIN"):
            self.send(b"\r\n+CPIN: READY\r\n")
            self.ok()
            return
        if line.startswith("AT+CSQ"):
            self.send(b"\r\n+CSQ: 24,99\r\n")
            self.ok()
            return
        if line.startswith("AT+CEREG"):
            self.send(b'\r\n+CEREG: 2,1,"AB12","0123456789"\r\n')
            self.ok()
            return
        if line.startswith("AT+CREG"):
            self.send(b'\r\n+CREG: 2,1,"AB12","0123456789"\r\n')
            self.ok()
            return
        if line.startswith("AT+COPS"):
            self.send(b'\r\n+COPS: 0,0,"FakeCarrier"\r\n')
            self.ok()
            return
        if line.startswith("AT+QNWINFO"):
            self.send(b'\r\n+QNWINFO: "FDD","B2","LTE 1900",2350\r\n')
            self.ok()
            return
        if line.startswith("AT+QCCID"):
            self.send(b"\r\n+QCCID: 89860000000000000000\r\n")
            self.ok()
            return
        if line.startswith("AT+CCID"):
            self.send(b"\r\n+CCID: 89860000000000000000\r\n")
            self.ok()
            return
        if line.startswith("AT+CNUM"):
            self.send(f'\r\n+CNUM: "","{OWN_NUMBER}",129\r\n'.encode())
            self.ok()
            return
        if line.startswith("ATI"):
            self.send(b"\r\nRM520N-GL\r\nRevision: FAKE 1.0\r\n")
            self.ok()
            return
        # init ladder + everything else
        self.ok()

    def on_pdu_submit(self, raw):
        hexstr = raw.decode("ascii", "ignore").strip().upper()
        self.cmgs_count += 1
        self.submitted_pdus.append(hexstr)
        tp = bytes.fromhex(hexstr)
        # 00 (SMSC len) | fo | MR | DA-len | toa | digits…
        mr = tp[2]
        da_len = tp[3]
        da_digits = unpack_semi(tp[5:5 + da_len // 2 + (da_len & 1)])
        self.send(f"\r\n+CMGS: {mr}\r\n".encode())
        self.ok()
        # asynchronous delivery report for that MR
        pdu, _ = cds_pdu(mr, da_digits)
        self.send(f"\r\n+CDS: {len(pdu) // 2 - 1}\r\n{pdu}\r\n".encode())
        self.cds_sent += 1

    def stage_inbound(self, idx, sender, text, ref=0, part=1, total=1):
        """Script a stored message + fire the CMTI notification."""
        pdu, _ = deliver_pdu(sender, text, ref, part, total)
        with self.lock:
            self.staged[idx] = pdu
        self.send(f'\r\n+CMTI: "ME",{idx}\r\n'.encode())


def unpack_semi(b):
    out = ""
    for octet in b:
        lo, hi = octet & 0x0F, (octet >> 4) & 0x0F
        out += (chr(lo + 48) if lo < 10 else "") + (chr(hi + 48) if hi < 10 else "")
        if lo == 0x0F:
            out = out[:-1]
        if hi == 0x0F:
            break
    return out.rstrip("F")


def re_partition(buf):
    """Split at the first CR or LF (tolerating CRLF as one)."""
    i_cr, i_lf = buf.find(b"\r"), buf.find(b"\n")
    if i_cr == -1:
        i = i_lf
    elif i_lf == -1:
        i = i_cr
    else:
        i = min(i_cr, i_lf)
    return buf[:i], b"", buf[i + 1:]


class WebhookReceiver(http.server.BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        sig = self.headers.get("X-Webhook-Signature", "")
        WebhookReceiver.received.append((body, sig))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def http_req(method, path, body=None, token=None, base=f"http://127.0.0.1:{PORT}", raw=False):
    url = base + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            payload = r.read()
            return r.status, (payload if raw else (json.loads(payload) if payload else None))
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload)
        except Exception:
            return e.code, payload


def sse_reader(path, token, timeout=15, last_event_id=None):
    """Consume SSE events into a list; returns (events, last_id).
    Events carry `id:` + `data:` (no `event:` field); the type lives in
    data["type"]. Reconnect cursor is the Last-Event-ID header."""
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}")
    req.add_header("Authorization", f"Bearer {token}")
    if last_event_id is not None:
        req.add_header("Last-Event-ID", str(last_event_id))
    r = urllib.request.urlopen(req, timeout=timeout)
    events = []
    last_id = None
    ev = {}
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            line = r.readline()
        except TimeoutError:
            break  # idle stream: return what we captured
        if not line:
            break
        line = line.decode().rstrip("\n")
        if line.startswith(":"):
            continue  # heartbeat/comment
        if line == "":
            if ev.get("data"):
                ev["data"] = json.loads(ev["data"])
                events.append(ev)
                if len(events) >= 3:
                    break
            ev = {}
            continue
        if line.startswith("data:"):
            ev["data"] = line[5:].strip()
        elif line.startswith("id:"):
            ev["id"] = int(line[3:].strip())
            last_id = ev["id"]
    r.close()
    return events, last_id


def wait_for(cond, timeout=20, interval=0.3, desc="condition"):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(interval)
    return None


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    binary, workdir = os.path.abspath(sys.argv[1]), sys.argv[2]
    os.makedirs(workdir, exist_ok=True)
    self_check_packing()

    modem = FakeModem()
    modem.start()
    # seed one stored message: the boot CMGL import must decode it into
    # the inbox and delete it by CMGL index (not by its length)
    stored_hex, _ = deliver_pdu(SMS_DEST, "boot-import stored message")
    modem.stored_cmgl.append((7, stored_hex))

    cfg_path = os.path.join(workdir, "config.toml")
    with open(cfg_path, "w") as f:
        f.write(f"""listen = "127.0.0.1:{PORT}"
db_path = "{workdir}/cellmatik.db"
serial_path = "{modem.slave_path}"
modem_profile = "rm520n"
queue_limit = 32
heartbeat_s = 20
default_delivery_report = true
stale_after_s = 120
submit_retries = 3
retry_interval_s = 60
max_segments = 10
csmp_vp = 167

[voice]
audio_device = "default"
audio_codec = "g711u"

[retention]
mode = "none"

[mms]
enabled = false
manage_interface = "cellmatik"
""")

    # webhook receiver on a free port
    hook_srv_port = 18100
    hook = threading.Thread(
        target=lambda: http.server.HTTPServer(("127.0.0.1", hook_srv_port), WebhookReceiver).serve_forever(),
        daemon=True,
    )
    hook.start()

    log = open(os.path.join(workdir, "cellmatik.log"), "w")
    proc = subprocess.Popen(
        [binary, "--config", cfg_path],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        run_checks(binary, cfg_path, modem, workdir, hook_srv_port)
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
        modem.stop = True
        log.close()

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("FAILED: " + ", ".join(f[0] for f in failed))
        return 1
    return 0


def run_checks(binary, cfg_path, modem, workdir, hook_port):
    # --- token bootstrap ---
    r = subprocess.run([binary, "--config", cfg_path, "token", "add", "e2e"],
                       capture_output=True, text=True, timeout=10)
    token = None
    for line in r.stdout.splitlines():
        # token printed exactly once; find the 64-hex token
        words = line.split()
        for w in words:
            if len(w) == 64 and all(c in "0123456789abcdef" for c in w):
                token = w
    if not check("token add prints a 64-hex token", token, r.stdout + r.stderr):
        return

    # --- service up ---
    def healthz():
        try:
            s, _ = http_req("GET", "/healthz")
            return s == 200
        except Exception:
            return False
    check("healthz 200", wait_for(healthz, 15))

    # --- auth ---
    s, _ = http_req("GET", "/v1/status")
    check("401 without token", s == 401, f"got {s}")
    s, _ = http_req("GET", "/v1/status", token="f" * 64)
    check("401 with bogus token", s == 401, f"got {s}")

    # --- status: modem becomes ready ---
    def ready():
        s, body = http_req("GET", "/v1/status", token=token)
        if s != 200:
            return None
        return body if body and body.get("sim", {}).get("state") in ("ready", "ok") or True else None
    st = wait_for(ready, 20)
    if check("status 200 after boot", st is not None):
        check("status own_number", st.get("sim", {}).get("msisdn") == OWN_NUMBER,
              json.dumps(st.get("sim", {})))
        check("status voice unsupported (rm520n)", st.get("voice", {}).get("supported") is False)
        check("status mms disabled", st.get("mms", {}).get("enabled") is False)
        check("status bearer disabled", st.get("mms", {}).get("bearer") == "disabled")
        check("status modem ready", st.get("modem", {}).get("state") == "ready",
              str(st.get("modem", {})))
        check("status iccid", bool(st.get("sim", {}).get("iccid")), str(st.get("sim", {}).get("iccid")))

    # --- boot CMGL import: stored message decoded + deleted by index ---
    def imported_row():
        s, b = http_req("GET", "/v1/messages", token=token)
        for m in (b or {}).get("messages", []):
            if m.get("text") == "boot-import stored message":
                return m
        return None
    row = wait_for(imported_row, 10)
    check("boot import → inbox row", row is not None, "no imported row")
    check("boot import deleted by index", 7 in modem.cmgd_indices,
          f"cmgd={modem.cmgd_indices}")

    # --- 422 shapes ---
    s, body = http_req("POST", "/v1/sms", {"to": "123", "text": "x"}, token=token)
    check("422 malformed to", s == 422 and body and body.get("error") in ("malformed", "invalid_to", "field:to"),
          f"{s} {body}")
    s, body = http_req("POST", "/v1/sms", {"to": SMS_DEST}, token=token)
    check("422 missing text", s == 422, f"{s} {body}")

    # --- single-segment send → CDS → delivered ---
    text1 = "e2e single hello"
    s, item = http_req("POST", "/v1/sms", {"to": SMS_DEST, "text": text1}, token=token)
    if check("POST /v1/sms 202", s == 202, f"got {s} {item}"):
        check("item pending", item.get("status") == "pending", str(item))
        sid = item["id"]
        got = wait_for(lambda: (http_req("GET", f"/v1/sms/{sid}", token=token)[1] or {}).get("status") == "delivered", 20)
        check("single sms delivered via CDS", got, "outbox stuck")
        s, final = http_req("GET", f"/v1/sms/{sid}", token=token)
        check("delivered_at stamped", final and final.get("delivered_at"), str(final))
        check("segments=1", final.get("segments") == 1)
        check("attempts==1 (no re-claim churn)", final.get("attempts") == 1, str(final.get("attempts")))
    check("fake modem saw 1 CMGS", modem.cmgs_count >= 1, str(modem.cmgs_count))
    check("CDS sent", modem.cds_sent >= 1)

    # --- multi-segment send ---
    text2 = "m" * 350  # 350 chars → 3 segments (153×2 + 44)
    s, item = http_req("POST", "/v1/sms", {"to": SMS_DEST, "text": text2}, token=token)
    if check("POST multi 202", s == 202, f"got {s}"):
        sid = item["id"]
        want_segments = item.get("segments")
        check("350 chars → 3 segments", want_segments == 3, str(want_segments))
        got = wait_for(lambda: (http_req("GET", f"/v1/sms/{sid}", token=token)[1] or {}).get("status") == "delivered", 30)
        check("multi-segment delivered", got)
    check("3 more CMGS", modem.cmgs_count >= 4, str(modem.cmgs_count))

    # --- inbound concat → one inbox row + SSE ---
    sse = threading.Thread(target=run_sse, args=(token,), daemon=True)
    sse.start()
    time.sleep(0.5)

    part_a = "alpha " * 30   # 180 chars → over one segment → concat 2
    part_b = "beta " * 30
    modem.stage_inbound(10, SMS_DEST, part_a, ref=77, part=1, total=2)
    modem.stage_inbound(11, SMS_DEST, part_b, ref=77, part=2, total=2)

    def inbox_row():
        s, body = http_req("GET", "/v1/messages", token=token)
        rows = (body or {}).get("messages") or []
        for row in rows:
            if part_a[:10] in (row.get("text") or ""):
                return row
        return None
    row = wait_for(inbox_row, 20)
    if check("concat inbound → one inbox row", row, "no completed row"):
        check("concat text complete", row.get("text") == part_a + part_b, repr(row.get("text"))[-60:])
        check("inbox from", row.get("from") == SMS_DEST, str(row.get("from")))
        check("inbox channel sms", row.get("channel") == "sms")

    # wait for the SSE thread to have observed the live event
    sse.join(timeout=10)
    if SSE_EVENTS:
        check("SSE live message event", any(e["data"].get("type") == "message" for e in SSE_EVENTS),
              str([e["data"].get("type") for e in SSE_EVENTS]))
        last_id = max((e.get("id") or 0) for e in SSE_EVENTS)
        replayed, _ = sse_reader("/v1/events", token, timeout=6, last_event_id=last_id - 1)
        check("SSE replay from Last-Event-ID", any(e["data"].get("type") == "message" for e in replayed),
              f"{len(replayed)} replayed")
    else:
        check("SSE live message event", False, "no SSE events captured")

    # --- webhook: register, deliver, verify HMAC ---
    s, body = http_req("PUT", "/v1/webhook", {"url": f"http://127.0.0.1:{hook_port}/hook"}, token=token)
    if check("PUT webhook 200 + secret", s == 200 and body and body.get("secret"), f"{s} {body}"):
        secret = body["secret"].encode()
        check("webhook secret is 64-hex", len(body["secret"]) == 64)
        s, wh = http_req("GET", "/v1/webhook", token=token)
        check("GET webhook no secret leak", s == 200 and "secret" not in (wh or {}), str(wh))
        WebhookReceiver.received.clear()
        modem.stage_inbound(12, OWN_NUMBER, "hook me", ref=0, part=1, total=1)
        got = wait_for(lambda: WebhookReceiver.received, 20)
        if check("webhook delivered", got):
            payload, sig = got[0]
            mac = hmac.new(secret, payload, hashlib.sha256).hexdigest()
            check("webhook HMAC sha256= valid", sig == f"sha256={mac}", f"{sig} vs sha256={mac}")
            env = json.loads(payload)
            check("webhook envelope type=message", env.get("type") == "message", str(env))
            check("webhook data text", env.get("data", {}).get("text") == "hook me", str(env))

    # --- read + delete ---
    if row:
        s, body = http_req("POST", f"/v1/messages/{row['id']}/read", token=token)
        check("mark read 200 + read=true", s == 200 and (body or {}).get("read") is True, f"{s} {body}")
        s, _ = http_req("DELETE", f"/v1/messages/{row['id']}", token=token)
        check("delete message 204", s == 204, f"got {s}")
        # spec has no GET /v1/messages/{id} — the route must not exist
        s, _ = http_req("GET", f"/v1/messages/{row['id']}", token=token)
        check("no GET /v1/messages/{id} route (405)", s == 405, f"got {s}")
        # deletion is observable through the list
        def gone():
            s2, body2 = http_req("GET", "/v1/messages", token=token)
            return all(m.get("id") != row["id"] for m in ((body2 or {}).get("messages") or []))
        check("deleted message gone from list", wait_for(gone, 5))

    # --- list envelope ---
    s, body = http_req("GET", "/v1/sms", token=token)
    check("GET /v1/sms items envelope", s == 200 and isinstance((body or {}).get("items"), list), str(body)[:200])


SSE_EVENTS = []


def run_sse(token):
    try:
        events, _ = sse_reader("/v1/events", token, timeout=8)
        SSE_EVENTS.extend(events)
    except Exception as e:
        print("SSE reader error:", repr(e), flush=True)


if __name__ == "__main__":
    sys.exit(main())
