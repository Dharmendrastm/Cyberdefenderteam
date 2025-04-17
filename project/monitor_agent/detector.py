from scapy.all import TCP
def detect_threat(packet):
    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        
        # Example rule: Telnet (port 23) is insecure.
        if dport == 23 or sport == 23:
            return "Unauthorized Telnet access detected"
        
        # Example rule: If ports associated with common services are being scanned.
        if dport in [22, 80, 443] and sport < 1024:
            return "Possible port scanning attempt detected"
    

    return None
