from scapy.all import sniff, IP, TCP
from core.rule_engine import apply_rules
from loguru import logger
import json

def process_packet(packet):
    try:
        alert = apply_rules(packet)
        if alert:
            with open("alerts/alert_log.json", "a") as f:
                f.write(json.dumps(alert) + "\n")
            logger.warning(f"ALERT: {alert['message']} from {alert['source_ip']}")
    except Exception as e:
        logger.error(f"Error: {e}")

def start_sniffing(interface="eth0"):
    logger.info(f"Starting packet sniffing on {interface}...")
    sniff(prn=process_packet, iface=interface, store=False)

if __name__ == "__main__":
    start_sniffing()
