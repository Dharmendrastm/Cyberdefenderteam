from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from detector import detect_threat
import sys
import os

# Ensure the root project directory is in the path for module resolution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), r'C:\Users\dharm\Desktop\project\web_dashboard\app.py')))

# Import alert_received from the web_dashboard package
from web_dashboard.app import alert_received # type: ignore

def log_packet(pkt_info):
    with open("logs/traffic_log.db", "a") as f:
        f.write(pkt_info + "\n")
        
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"

        log_line = f"[{datetime.now()}] {src_ip} --> {dst_ip} | Protocol: {proto}"
        print(log_line)
        log_packet(log_line)

        # Threat detection
        threat = detect_threat(packet)
        if threat:
            alert_msg = f"[ALERT] {threat} | {src_ip} --> {dst_ip}"
            print(alert_msg)
            log_packet(alert_msg)
            # Send alert to Flask (backend)
            alert_received(alert_msg)

# Start sniffing (eth0 = network interface)
print("Starting packet sniffing...")
sniff(prn=analyze_packet, store=0)
