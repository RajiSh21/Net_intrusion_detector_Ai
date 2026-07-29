import socketio
import time
import datetime

sio = socketio.Client()
sio.connect('http://localhost:5000')

print("Connected. Emitting test packet...")
sio.emit('new_packet', {
    "timestamp": datetime.datetime.now().isoformat(),
    "src": "192.168.1.1",
    "dst": "10.0.0.5",
    "sport": 12345,
    "dport": 80,
    "proto": "TCP",
    "verdict": "Port Scan",
    "confidence": 0.95,
    "length": 500,
    "latencyMs": 1.2
})

time.sleep(1)
sio.disconnect()
print("Done.")
