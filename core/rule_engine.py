# core/rule_engine.py

from scapy.layers.inet import TCP, IP
from datetime import datetime

connection_tracker = {}

def apply_rules(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst
    destination_port = tcp_layer.dport
    flags = tcp_layer.flags
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # RULE 1: Detect suspicious Telnet connection (port 23)
    if destination_port == 23:
        return {
            "type": "Telnet Connection",
            "message": "Telnet connection detected (unencrypted protocol)",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "timestamp": timestamp
        }

    # RULE 2: Detect potential brute force login (multiple SYNs from same IP)
    if flags == "S":  # SYN flag
        if source_ip not in connection_tracker:
            connection_tracker[source_ip] = []
        connection_tracker[source_ip].append(datetime.now())

        # Keep only last 10 seconds of traffic
        connection_tracker[source_ip] = [
            t for t in connection_tracker[source_ip]
            if (datetime.now() - t).seconds < 10
        ]

        if len(connection_tracker[source_ip]) > 15:
            return {
                "type": "Brute Force Attempt",
                "message": f"Possible brute force attack - {len(connection_tracker[source_ip])} SYN packets in 10s",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "timestamp": timestamp
            }

    # RULE 3: Detect SYN flood (DoS attack)
    if flags == "S":
        syn_count = sum(1 for t in connection_tracker.get(source_ip, []) if (datetime.now() - t).seconds < 5)
        if syn_count > 25:
            return {
                "type": "SYN Flood",
                "message": "SYN Flood detected (possible DoS attack)",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "timestamp": timestamp
            }

    return None
