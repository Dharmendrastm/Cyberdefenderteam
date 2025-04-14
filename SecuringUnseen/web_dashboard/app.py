from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from monitor_agent.sniffer import send_alert_to_flask  # This will be our interface to sniffer

app = Flask(__name__)
socketio = SocketIO(app)

# Serve the dashboard page
@app.route('/')
def index():
    return render_template('index.html')

# SocketIO event to handle incoming alerts
@socketio.on('connect')
def handle_connect():
    print("Client connected!")

# Function to receive alerts from sniffer and send to frontend
def alert_received(alert_msg):
    print(f"Alert received: {alert_msg}")
    socketio.emit('new_alert', {'msg': alert_msg})

# Link the sniffer module to call this function for every alert
send_alert_to_flask(alert_received)

# Run the app
if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5000)
