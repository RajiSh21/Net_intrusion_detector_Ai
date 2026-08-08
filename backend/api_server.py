
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import re
import smtplib
from email.message import EmailMessage
import random
from datetime import datetime, timedelta

def send_verification_email(to_email, code, action):
    # DUMMY CONFIG FOR NOW - can be overridden via ENV vars
    sender_email = os.environ.get('SMTP_EMAIL', 'noreply.nids.app@gmail.com')
    sender_password = os.environ.get('SMTP_PASSWORD', 'ssdv cnpi mqvi tiln')
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    
    action_text = "registering a new account" if action == 'register' else "resetting your password"
    
    msg = EmailMessage()
    msg['Subject'] = 'NIDS - Verification Code'
    msg['From'] = sender_email
    msg['To'] = to_email
    
    # Plain text fallback
    msg.set_content(f"You are {action_text}.\nYour 4-digit verification code is: {code}\nThis code will expire in 10 minutes.")
    
    # HTML version
    html_content = f"""\
    <html>
      <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #0f172a;">NIDS Security Verification</h2>
        <p>Hello,</p>
        <p>We received a request for <strong>{action_text}</strong>. Please use the verification code below to complete the process:</p>
        <div style="background-color: #f1f5f9; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0;">
          <span style="font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #2563eb;">{code}</span>
        </div>
        <p style="font-size: 14px; color: #64748b;">This code will expire in 10 minutes. If you did not request this, you can safely ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin-top: 30px;" />
        <p style="font-size: 12px; color: #94a3b8; text-align: center;">Network Intrusion Detection System</p>
      </body>
    </html>
    """
    msg.add_alternative(html_content, subtype='html')
    
    print(f"--- DUMMY EMAIL SENT TO {to_email} WITH CODE {code} ---")
    
    # We will try to send the email, but catch exception so it doesn't break if dummy config is used.
    if sender_email != 'dummy@example.com':
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            print(f"Failed to send real email: {e}")


app = Flask(__name__)
CORS(app)
# Enable CORS for the dashboard
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

@socketio.on('connect')
def test_connect():
    print("Client connected")

@socketio.on('disconnect')
def test_disconnect():
    print("Client disconnected")

@socketio.on('new_packet')
def handle_new_packet(data):
    print("Received new packet:", data)
    # Broadcast to all connected web clients
    emit('packet_update', data, broadcast=True)

@app.route('/api/model_info')
def get_model_info():
    return jsonify({
        "algorithm": "XGBoost",
        "trainingSamples": 73362,
        "ganAugmented": True,
        "accuracy": "84.32%",
        "classes": ["Normal", "Dos/DDos", "PortScan", "Brute Force", "Web Attack", "Botnet ARES", "Infiltration"]
    })

@app.route('/api/stats')
def get_stats():
    try:
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'nids.db')
        
        threats_found = 0
        total_analyzed = 0
        monitored_hosts = 0

        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ALERT'")
            if cursor.fetchone() is not None:
                cursor.execute("SELECT COUNT(*) FROM ALERT")
                threats_found = cursor.fetchone()[0]
                
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='TRAFFIC_LOG'")
            if cursor.fetchone() is not None:
                cursor.execute("SELECT COUNT(*) FROM TRAFFIC_LOG")
                total_analyzed = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM TRAFFIC_LOG")
                monitored_hosts = cursor.fetchone()[0]
            conn.close()
            
        return jsonify({
            "threatsFound": threats_found,
            "totalAnalyzed": total_analyzed,
            "monitoredHosts": monitored_hosts
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/logs')
def get_logs():
    try:
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'nids.db')
        if not os.path.exists(db_path):
            return jsonify([])
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='TRAFFIC_LOG'")
        if cursor.fetchone() is None:
            conn.close()
            return jsonify([])
            
        cursor.execute('''
            SELECT source_ip, destination_ip, port, protocol, classification, timestamp 
            FROM TRAFFIC_LOG 
            ORDER BY log_id DESC LIMIT 500
        ''')
        rows = cursor.fetchall()
        conn.close()
        
        packets = []
        for i, row in enumerate(rows):
            src, dst, port, proto, cls, ts = row
            packets.append({
                "id": f"log-{i}",
                "time": ts,
                "src": src,
                "dst": dst,
                "proto": proto,
                "size": 0,
                "flags": "...",
                "sev": "Low" if cls == "Normal" else "High",
                "type": cls,
                "verdict": cls
            })
        return jsonify(packets)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/alerts')
def get_alerts():
    try:
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'nids.db')
        if not os.path.exists(db_path):
            return jsonify([])
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ALERT'")
        if cursor.fetchone() is None:
            conn.close()
            return jsonify([])
            
        cursor.execute('''
            SELECT a.alert_id, a.severity_level, a.generated_at, t.classification, t.source_ip, t.destination_ip
            FROM ALERT a
            JOIN TRAFFIC_LOG t ON a.log_id = t.log_id
            ORDER BY a.alert_id DESC
        ''')
        rows = cursor.fetchall()
        conn.close()
        
        alerts = []
        for row in rows:
            aid, sev, ts, cls, src, dst = row
            alerts.append({
                "id": f"ALT-{str(aid).zfill(4)}",
                "time": ts,
                "type": cls,
                "severity": sev,
                "srcIp": src,
                "destIp": dst
            })
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/send-code', methods=['POST'])
def send_code():
    data = request.json
    action = data.get('action') # 'register' or 'reset'
    email = data.get('email')
    username = data.get('username')
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
        
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'nids.db')
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Ensure tables exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS USER (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                role TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS VERIFICATION_CODES (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                code TEXT,
                timestamp DATETIME,
                action TEXT
            )
        ''')
        
        if action == 'register':
            if not username:
                return jsonify({"error": "Username is required for registration"}), 400
            cursor.execute("SELECT * FROM USER WHERE username = ?", (username,))
            if cursor.fetchone():
                conn.close()
                return jsonify({"error": "Username already exists"}), 400
        elif action == 'reset':
            cursor.execute("SELECT * FROM USER WHERE email = ?", (email,))
            if not cursor.fetchone():
                conn.close()
                return jsonify({"error": "No account found with that email address"}), 404
        else:
            return jsonify({"error": "Invalid action"}), 400
            
        code = str(random.randint(1000, 9999))
        timestamp = datetime.now()
        
        cursor.execute("INSERT INTO VERIFICATION_CODES (email, code, timestamp, action) VALUES (?, ?, ?, ?)", 
                       (email, code, timestamp, action))
        conn.commit()
        conn.close()
        
        send_verification_email(email, code, action)
        return jsonify({"success": True, "message": "Verification code sent"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    first_name = data.get('firstName', '')
    last_name = data.get('lastName', '')
    email = data.get('email', '')
    contact = data.get('contact', '')
    code = data.get('code')
    role = 'Security Analyst' # default role
    
    if not username or not password or not first_name or not email or not code:
        return jsonify({"error": "Required fields are missing, including verification code"}), 400

    if not re.match(r'^[a-zA-Z0-9._]+$', username):
        return jsonify({"error": "Username can only contain letters, numbers, dots, and underscores."}), 400

    if re.search(r'[._]{2,}', username):
        return jsonify({"error": "Username cannot contain consecutive dots or underscores."}), 400

    if username.lower() == password.lower():
        return jsonify({"error": "Username and password cannot be identical"}), 400

    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'nids.db')
    
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Ensure table exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS USER (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                role TEXT
            )
        ''')
        
        # Check if user exists
        cursor.execute("SELECT * FROM USER WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "Username already exists"}), 400
            
        # Verify Code
        cursor.execute("SELECT code, timestamp FROM VERIFICATION_CODES WHERE email = ? AND action = 'register' ORDER BY timestamp DESC LIMIT 1", (email,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "No verification code requested for this email"}), 400
            
        stored_code, timestamp_str = row
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        if datetime.now() - timestamp > timedelta(minutes=10):
            conn.close()
            return jsonify({"error": "Verification code expired. Please request a new one."}), 400
            
        if stored_code != code:
            conn.close()
            return jsonify({"error": "Invalid verification code"}), 400

        password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%]).{8,}$"
        if not re.match(password_regex, password):
            conn.close()
            return jsonify({"error": "Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character (!@#$%)."}), 400

        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            conn.close()
            return jsonify({"error": "Please enter a valid email address."}), 400

        hashed_pw = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO USER (username, password_hash, first_name, last_name, email, role) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, hashed_pw, first_name, last_name, email, role))
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Registration successful"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'nids.db')
    
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Ensure table exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS USER (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                role TEXT
            )
        ''')
        
        cursor.execute("SELECT user_id, username, password_hash, first_name, last_name, email, role FROM USER WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({"error": "User is not registered"}), 404

        if check_password_hash(user[2], password):
            return jsonify({
                "success": True, 
                "user": {
                    "user_id": user[0],
                    "username": user[1],
                    "firstName": user[3],
                    "lastName": user[4],
                    "email": user[5],
                    "role": user[6]
                }
            })
        else:
            return jsonify({"error": "Password doesn't match"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('newPassword')
    code = data.get('code')

    if not email or not new_password or not code:
        return jsonify({"error": "Email, new password, and verification code are required"}), 400

    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'nids.db')
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT username FROM USER WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({"error": "No account found with that email address"}), 404
            
        username = user[0]
        if username.lower() == new_password.lower():
            conn.close()
            return jsonify({"error": "Password cannot be identical to your username"}), 400
            
        # Verify Code
        cursor.execute("SELECT code, timestamp FROM VERIFICATION_CODES WHERE email = ? AND action = 'reset' ORDER BY timestamp DESC LIMIT 1", (email,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "No verification code requested for this email"}), 400
            
        stored_code, timestamp_str = row
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        if datetime.now() - timestamp > timedelta(minutes=10):
            conn.close()
            return jsonify({"error": "Verification code expired. Please request a new one."}), 400
            
        if stored_code != code:
            conn.close()
            return jsonify({"error": "Invalid verification code"}), 400

        password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%]).{8,}$"
        if not re.match(password_regex, new_password):
            conn.close()
            return jsonify({"error": "Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character (!@#$%)."}), 400

        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            conn.close()
            return jsonify({"error": "Please enter a valid email address."}), 400

        hashed_pw = generate_password_hash(new_password)
        cursor.execute("UPDATE USER SET password_hash = ? WHERE email = ?", (hashed_pw, email))
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Password reset successful"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting NIDS API Server on http://0.0.0.0:{port}")
    socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
