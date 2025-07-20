from scapy.all import IP, TCP, UDP
from loguru import logger

# Example malicious IPs and ports (could be loaded from DB or external source)
MALICIOUS_IPS = {"45.33.32.156", "198.51.100.23"}
MALICIOUS_PORTS = {6667, 1337, 23, 5000}

def is_malicious(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if src_ip in MALICIOUS_IPS or dst_ip in MALICIOUS_IPS:
            logger.warning(f"⚠️ Malicious IP detected: {src_ip} → {dst_ip}")
            return True

        if TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport

            if sport in MALICIOUS_PORTS or dport in MALICIOUS_PORTS:
                logger.warning(f"⚠️ Suspicious port activity: {sport} → {dport}")
                return True

    return False
