
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import re

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
        "accuracy": "99.00%",
        "classes": ["Normal", "Dos/DDos", "PortScan", "Brute Force", "Web Attack", "Botnet ARES", "Infiltration"]
    })

@app.route('/api/stats')
def get_stats():
    try:
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs', 'alerts.db')
        
        if not os.path.exists(db_path):
            threats_found = 0
        else:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            # check if table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ALERT'")
            if cursor.fetchone() is None:
                threats_found = 0
            else:
                cursor.execute("SELECT COUNT(*) FROM ALERT")
                threats_found = cursor.fetchone()[0]
            conn.close()
        return jsonify({
            "threatsFound": threats_found,
            "totalAnalyzed": 0 # Difficult to track without a separate counter collection, handled client-side for live
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    first_name = data.get('firstName', '')
    last_name = data.get('lastName', '')
    email = data.get('email', '')
    contact = data.get('contact', '')
    role = 'Security Analyst' # default role
    
    if not username or not password or not first_name or not email:
        return jsonify({"error": "Required fields are missing"}), 400

    if bool(re.search(r'\d', username)):
        return jsonify({"error": "Username cannot contain numbers"}), 400

    if username.lower() == password.lower():
        return jsonify({"error": "Username and password cannot be identical"}), 400

    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs', 'alerts.db')
    
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Ensure table exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ADMINISTRATOR (
                admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password_hash TEXT,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                contact TEXT,
                role TEXT
            )
        ''')
        
        # Check if user exists
        cursor.execute("SELECT * FROM ADMINISTRATOR WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "Username already exists"}), 400
            
        hashed_pw = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO ADMINISTRATOR (username, password_hash, first_name, last_name, email, contact, role) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, hashed_pw, first_name, last_name, email, contact, role))
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

    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs', 'alerts.db')
    
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Ensure table exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ADMINISTRATOR (
                admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password_hash TEXT,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                contact TEXT,
                role TEXT
            )
        ''')
        
        cursor.execute("SELECT admin_id, username, password_hash, first_name, last_name, email, contact, role FROM ADMINISTRATOR WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({"error": "User is not registered"}), 404

        if check_password_hash(user[2], password):
            return jsonify({
                "success": True, 
                "user": {
                    "admin_id": user[0],
                    "username": user[1],
                    "firstName": user[3],
                    "lastName": user[4],
                    "email": user[5],
                    "contact": user[6],
                    "role": user[7]
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

    if not email or not new_password:
        return jsonify({"error": "Email and new password are required"}), 400

    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs', 'alerts.db')
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT username FROM ADMINISTRATOR WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({"error": "No account found with that email address"}), 404
            
        username = user[0]
        if username.lower() == new_password.lower():
            conn.close()
            return jsonify({"error": "Password cannot be identical to your username"}), 400
            
        hashed_pw = generate_password_hash(new_password)
        cursor.execute("UPDATE ADMINISTRATOR SET password_hash = ? WHERE email = ?", (hashed_pw, email))
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Password reset successful"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("Starting NIDS API Server on http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
