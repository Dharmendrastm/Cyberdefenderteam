# sniffer.py

from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from monitor_agent.detector import detect_threat
from web_dashboard.app import alert_received  # Import the Flask alert function

# Store logs
def log_packet(pkt_info):
    with open("logs/traffic_log.db", "a") as f:
        f.write(pkt_info + "\n")

# Analyze each captured packet
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
