
from flask import Flask, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import pymongo

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
        client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
        db = client["nids"]
        alerts = db["alerts"]
        threats_found = alerts.count_documents({})
        return jsonify({
            "threatsFound": threats_found,
            "totalAnalyzed": 0 # Difficult to track without a separate counter collection, handled client-side for live
        })
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    print("Starting NIDS API Server on http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
