from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from core.rule_engine import apply_rules

def test_syn_flood():
    pkt = IP(src="192.168.0.1", dst="192.168.0.2")/TCP(flags="S")
    for _ in range(25):
        alert = apply_rules(pkt)
    assert alert is not None
