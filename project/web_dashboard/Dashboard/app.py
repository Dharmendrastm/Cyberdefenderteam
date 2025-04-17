from flask import Flask, render_template
from flask_socketio import SocketIO
import sys
import os

# Try importing the sniffer alert function
try:
    from monitor_agent.sniffer import send_alert_to_flask
except ImportError as e:
    print(f"[ERROR] Unable to import sniffer module: {e}")
    send_alert_to_flask = None  # Fallback if module not found

app = Flask(__name__)
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print("[INFO] Client connected via SocketIO.")

def alert_received(alert_msg):
    print(f"[ALERT] Received: {alert_msg}")
    socketio.emit('new_alert', {'msg': alert_msg})

# Only link alert handler if sniffer is available
if send_alert_to_flask:
    send_alert_to_flask(alert_received)
else:
    print("[WARNING] Sniffer alerts won't be received as 'send_alert_to_flask' is not linked.")

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5000)
